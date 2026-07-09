import math, gc, time
from machine import ADC, PWM, Pin
from machine import disable_irq, enable_irq

# 全局配置（折中速度：慢于原版、快于上次低速版）

TRACK_CHANNEL_COUNT = 5
TRACK_PINS = [27, 33, 32, 35, 34]           # s0~s4
TRACK_ADC_ATTEN_DB = 11                     # 0~3.3V
TRACK_ADC_WIDTH = 12                        # 0~4095
TRACK_CENTROID_KP = 60.0                    # P: 位置误差 → 差速
TRACK_CENTROID_KD = 50                   # D: 误差变化率 → 提前转向
TRACK_LINE_IS_DARK = False                  # 白底黑线: 黑线通常 ADC 更低
TRACK_NOISE_FLOOR = 80                      # ADC/对比度噪声地板

MOTOR_A_IN1, MOTOR_A_IN2 = 15, 13           # 电机A (右)
MOTOR_B_IN1, MOTOR_B_IN2 = 25, 14           # 电机B (左)
MOTOR_PWM_FREQ = 5000
MOTOR_PWM_MAX = 65535
MOTOR_DUTY_MAX_PCT = 68                     # 全局最大占空比，折中提速
MOTOR_A_INVERT, MOTOR_B_INVERT = 1, 0       # 右轮机械反装

LED_GPIO = 22

ENC_A_A, ENC_A_B = 16, 17                   # 右编码器
ENC_B_A, ENC_B_B = 18, 19                   # 左编码器
ENC_SPIKE_LIMIT = 100
ENC_LPF_ALPHA = 0.1

MOTOR_LEFT_ENABLE, MOTOR_RIGHT_ENABLE = 1, 1
PID_LEFT_KP, PID_LEFT_KI, PID_LEFT_KD = 0.3, 0.02, 0.0
PID_RIGHT_KP, PID_RIGHT_KI, PID_RIGHT_KD = 0.3, 0.02, 0.0
CTRL_STARTUP_DELAY = 1000                   # 2ms × 1000 = 2s
CTRL_PERIOD_US = 2000

TRACK_BASE_SPEED = 22                       # PID模式基准转速小幅提高
USE_ENCODER_SPEED_PID = False                # 编码器稳定后再改 True
OPEN_LOOP_BASE_DUTY = 34                    # 开环直行基础占空比，折中速度
OPEN_LOOP_DIFF_GAIN = 0.36                  # 转向增益小幅提高，过弯响应更快
OPEN_LOOP_DUTY_MAX_PCT = 40                 # 开环转弯最高占空比
LOST_LINE_SPIN_DUTY =35                     # 丢线原地旋转速度小幅上调
LOST_LINE_DEBOUNCE = 20                     # 连续丢线 N 帧后才触发旋转

DEBUG_SEND_INTERVAL = 100

def _clamp(x, lo, hi):
    if x < lo: return lo
    if x > hi: return hi
    return x

def _abs_val(x):
    return -x if x < 0 else x

# PID 控制器

class PID:
    MODE_INC = 0
    MODE_POS = 1

    def __init__(self, kp, ki, kd, target=0.0, integral_max=0.0):
        self.kp, self.ki, self.kd = kp, ki, kd
        self.target = target
        self.control_value = 0.0
        self._last_error = 0.0
        self._before_last_error = 0.0
        self._integral = 0.0
        self._integral_max = 0.0
        if integral_max == 0.0:
            self._mode = self.MODE_INC
        else:
            self._mode = self.MODE_POS
            if ki != 0.0:
                self._integral_max = abs(integral_max / ki)

    def set_target(self, target):
        self.target = target

    def update(self, measured):
        if self._mode == self.MODE_INC:
            self._update_inc(measured)
        else:
            self._update_pos(measured)
        return self.control_value

    def _update_inc(self, measured):
        error = self.target - measured
        delta_error = error - self._last_error
        self.control_value += (
            self.kp * delta_error
            + self.ki * error
            + self.kd * (delta_error - (self._last_error - self._before_last_error))
        )
        self.control_value = max(-MOTOR_DUTY_MAX_PCT, min(MOTOR_DUTY_MAX_PCT, self.control_value))
        self._before_last_error = self._last_error
        self._last_error = error

    def _update_pos(self, measured):
        error = self.target - measured
        self._integral += error
        if self._integral_max > 0:
            if self._integral > self._integral_max:
                self._integral = self._integral_max
            elif self._integral < -self._integral_max:
                self._integral = -self._integral_max
        self.control_value = (
            self.kp * error + self.ki * self._integral
            + self.kd * (error - self._last_error)
        )
        self._last_error = error

    def reset(self):
        self.control_value = 0.0
        self._last_error = 0.0
        self._before_last_error = 0.0
        self._integral = 0.0

# 低通滤波器

class LowPassFilter:
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self._last_output = 0.0
        self._first = True

    @property
    def value(self):
        return self._last_output

    def update(self, value):
        if self._first:
            self._last_output = value
            self._first = False
        else:
            self._last_output = self.alpha * value + (1.0 - self.alpha) * self._last_output
        return self._last_output

    def reset(self):
        self._last_output = 0.0
        self._first = True

# 光电传感器 (ADC + 灰度质心)

class TrackSensor:
    def __init__(self):
        self._adc = []
        for gpio in TRACK_PINS:
            a = ADC(Pin(gpio))
            if TRACK_ADC_ATTEN_DB == 11:
                a.atten(ADC.ATTN_11DB)
            elif TRACK_ADC_ATTEN_DB == 6:
                a.atten(ADC.ATTN_6DB)
            else:
                a.atten(ADC.ATTN_2_5DB)
            if TRACK_ADC_WIDTH == 12:
                a.width(ADC.WIDTH_12BIT)
            elif TRACK_ADC_WIDTH == 11:
                a.width(ADC.WIDTH_11BIT)
            else:
                a.width(ADC.WIDTH_10BIT)
            self._adc.append(a)

        self.raw = [0] * TRACK_CHANNEL_COUNT
        self.centroid = 2.0
        self.error = 0.0
        self.diff = 0
        self.lost_line = False

    def sample(self):
        for i in range(TRACK_CHANNEL_COUNT):
            self.raw[i] = self._adc[i].read()

        if TRACK_LINE_IS_DARK:
            ref = self.raw[0]
            for i in range(1, TRACK_CHANNEL_COUNT):
                if self.raw[i] > ref:
                    ref = self.raw[i]
        else:
            ref = 0

        weighted = 0.0
        total = 0.0
        for i in range(TRACK_CHANNEL_COUNT):
            if TRACK_LINE_IS_DARK:
                v = max(0.0, float(ref - self.raw[i]) - TRACK_NOISE_FLOOR)
            else:
                v = max(0.0, float(self.raw[i]) - TRACK_NOISE_FLOOR)
            weighted += i * v
            total += v

        if total > 0.0:
            self.centroid = weighted / total
        else:
            self.centroid = 2.0

        self.error = self.centroid - 2.0
        self.diff = int(TRACK_CENTROID_KP * self.error)
        rmax = self.raw[0]
        rmin = self.raw[0]
        for i in range(1, TRACK_CHANNEL_COUNT):
            if self.raw[i] > rmax: rmax = self.raw[i]
            if self.raw[i] < rmin: rmin = self.raw[i]
        self.lost_line = (rmax - rmin) < TRACK_NOISE_FLOOR
        return (self.error, self.diff)

# 电机驱动

class Motor:
    def __init__(self, in1_gpio, in2_gpio, invert=False):
        self._invert = invert
        self._dbg_count = 0

        p1 = Pin(in1_gpio, Pin.OUT, value=0)
        p2 = Pin(in2_gpio, Pin.OUT, value=0)
        self._pwm1 = PWM(p1, freq=MOTOR_PWM_FREQ, duty=0)
        self._pwm2 = PWM(p2, freq=MOTOR_PWM_FREQ, duty=0)

    def set(self, duty):
        if self._invert:
            duty = -duty
        pct = max(-MOTOR_DUTY_MAX_PCT, min(MOTOR_DUTY_MAX_PCT, duty))
        pwm_val = MOTOR_PWM_MAX - (abs(pct) * MOTOR_PWM_MAX // 100)

        if duty > 0:
            self._pwm1.duty_u16(pwm_val)
            self._pwm2.duty_u16(MOTOR_PWM_MAX)
        elif duty < 0:
            self._pwm1.duty_u16(MOTOR_PWM_MAX)
            self._pwm2.duty_u16(pwm_val)
        else:
            self._pwm1.duty_u16(0)
            self._pwm2.duty_u16(0)

        # 启动后首次有输出了, 打印确认
        if pct > 0 and self._dbg_count < 3:
            self._dbg_count += 1
            print("MOTOR pid=%d pct=%d pwm=%d/%d" % (duty, pct, pwm_val, MOTOR_PWM_MAX))

    def stop(self):
        self._pwm1.duty_u16(0)
        self._pwm2.duty_u16(0)

class MotorDriver:
    def __init__(self):
        self.motor_a = Motor(MOTOR_A_IN1, MOTOR_A_IN2, invert=bool(MOTOR_A_INVERT))
        self.motor_b = Motor(MOTOR_B_IN1, MOTOR_B_IN2, invert=bool(MOTOR_B_INVERT))

    def set(self, left, right):
        self.motor_b.set(left)
        self.motor_a.set(right)

    def stop(self):
        self.motor_a.stop()
        self.motor_b.stop()

# 编码器 (Pin 中断正交解码)

class Encoder:
    DEBOUNCE_US = 150  # 消抖窗口: 150us, 太大会在高转速下丢掉脉冲

    def __init__(self, pin_a_num, pin_b_num, invert=False):
        self._invert = invert
        self._count = 0
        self._last_tick = 0
        self._pin_b = Pin(pin_b_num, Pin.IN, Pin.PULL_UP)
        pin_a = Pin(pin_a_num, Pin.IN, Pin.PULL_UP)
        pin_a.irq(trigger=Pin.IRQ_RISING | Pin.IRQ_FALLING, handler=self._isr)

    def _isr(self, pin):
        t = time.ticks_us()
        if t - self._last_tick < self.DEBOUNCE_US:
            return
        self._last_tick = t
        if self._pin_b.value():
            self._count += 1
        else:
            self._count -= 1

    def read_and_clear(self):
        state = disable_irq()
        cnt = self._count
        self._count = 0
        enable_irq(state)
        if self._invert:
            cnt = -cnt
        return cnt

class EncoderPair:
    def __init__(self):
        self.left = Encoder(ENC_B_A, ENC_B_B, invert=False)
        self.right = Encoder(ENC_A_A, ENC_A_B, invert=True)

    def read(self):
        return (self.left.read_and_clear(), self.right.read_and_clear())

#  Debug 输出

class DebugOutput:
    def __init__(self):
        self._count = 0

    def send_frame(self, data, ld, rd):
        self._count += 1
        print("[%5d %s] raw=%4d %4d %4d %4d %4d  c=%.2f e=%+.2f  "
              "Tl=%5.1f Tr=%5.1f  Ml=%5.1f Mr=%5.1f  Dl=%+3d Dr=%+3d" % (
            self._count,
            "pid" if USE_ENCODER_SPEED_PID else "open",
            int(data[0]), int(data[1]), int(data[2]), int(data[3]), int(data[4]),
            data[5], data[6],
            data[7], data[8],
            data[9], data[10],
            ld, rd))

# 控制循环

class WheelControl:
    def __init__(self, enable, kp, ki, kd):
        self.pid = PID(kp, ki, kd, target=0.0, integral_max=0.0)
        self.lpf = LowPassFilter(alpha=ENC_LPF_ALPHA)
        self.prev_count = 0
        self.duty = 0
        self.enable = enable

    def reset(self):
        self.pid.reset()
        self.lpf.reset()
        self.prev_count = 0
        self.duty = 0

class ControlLoop:
    def __init__(self):
        self.sensor = TrackSensor()
        self.motor = MotorDriver()
        self.encoder = EncoderPair()
        self.debug = DebugOutput()

        self.left = WheelControl(
            bool(MOTOR_LEFT_ENABLE), PID_LEFT_KP, PID_LEFT_KI, PID_LEFT_KD)
        self.right = WheelControl(
            bool(MOTOR_RIGHT_ENABLE), PID_RIGHT_KP, PID_RIGHT_KI, PID_RIGHT_KD)

        self._startup_tick = 0
        self._last_diff = 0
        self._last_error = 0.0
        self._step_count = 0
        self._lost_count = 0

    def _diff_from_error(self, error):
        diff = int(TRACK_CENTROID_KP * error
                   + TRACK_CENTROID_KD * (error - self._last_error))
        self._last_error = error
        abs_err = abs(error)
        if abs_err > 1.0:
            alpha = 0.7   # 大弯 → 快速跟上
        elif abs_err > 0.3:
            alpha = 0.4   # 中等 → 正常
        else:
            alpha = 0.25  # 直道 → 强滤波防抖
        self._last_diff = int((1.0 - alpha) * self._last_diff + alpha * diff)
        return self._last_diff

    @staticmethod
    def _spike_filter(cur, prev):
        if _abs_val(cur - prev) > ENC_SPIKE_LIMIT:
            return prev
        return cur

    def _wheel_control(self, w, target, active):
        if (not active) or (not w.enable):
            w.pid.reset()
            w.duty = 0
            return
        w.pid.set_target(target if active else 0.0)
        w.pid.update(w.lpf.value)
        cv = w.pid.control_value
        w.duty = int(_clamp(cv, -MOTOR_DUTY_MAX_PCT, MOTOR_DUTY_MAX_PCT))

    def _open_loop_control(self, half_diff, active):
        if not active:
            self.left.reset()
            self.right.reset()
            return
        

        turn = half_diff * OPEN_LOOP_DIFF_GAIN
        if self.left.enable:
            self.left.duty = int(_clamp(OPEN_LOOP_BASE_DUTY + turn,
                                        -OPEN_LOOP_DUTY_MAX_PCT,
                                        OPEN_LOOP_DUTY_MAX_PCT))
        else:
            self.left.duty = 0

        if self.right.enable:
            self.right.duty = int(_clamp(OPEN_LOOP_BASE_DUTY - turn,
                                         -OPEN_LOOP_DUTY_MAX_PCT,
                                         OPEN_LOOP_DUTY_MAX_PCT))
        else:
            self.right.duty = 0

    def _debug_frame(self, tl, tr):
        jf = [float(self.sensor.raw[i]) for i in range(TRACK_CHANNEL_COUNT)]
        jf.append(self.sensor.centroid)
        jf.append(self.sensor.error)
        jf.append(tl)
        jf.append(tr)
        jf.append(self.left.lpf.value)
        jf.append(self.right.lpf.value)
        return jf

    def step(self):
        self._step_count += 1

        error, _ = self.sensor.sample()

        if self.sensor.lost_line and self._startup_tick >= CTRL_STARTUP_DELAY:
            self._lost_count += 1
        else:
            self._lost_count = 0

        if self._lost_count >= LOST_LINE_DEBOUNCE:
            if self._lost_count == LOST_LINE_DEBOUNCE:
                print("LOST LINE: spinning (raw=%s)" % self.sensor.raw)
            self.left.duty = -LOST_LINE_SPIN_DUTY
            self.right.duty = LOST_LINE_SPIN_DUTY
            self.motor.set(self.left.duty, self.right.duty)
            return

        raw_left, raw_right = self.encoder.read()
        fl = self._spike_filter(raw_left, self.left.prev_count)
        self.left.prev_count = fl
        self.left.lpf.update(float(fl))

        fr = self._spike_filter(raw_right, self.right.prev_count)
        self.right.prev_count = fr
        self.right.lpf.update(float(fr))

        diff_smoothed = self._diff_from_error(error)
        half_diff = int(diff_smoothed / 2)
        target_left = float(TRACK_BASE_SPEED + half_diff)
        target_right = float(TRACK_BASE_SPEED - half_diff)

        self._startup_tick += 1
        active = self._startup_tick >= CTRL_STARTUP_DELAY
        if USE_ENCODER_SPEED_PID:
            self._wheel_control(self.left, target_left, active)
            self._wheel_control(self.right, target_right, active)
        else:
            self._open_loop_control(half_diff, active)

        self.motor.set(self.left.duty, self.right.duty)

        if self._step_count % DEBUG_SEND_INTERVAL == 0:
            self.debug.send_frame(self._debug_frame(target_left, target_right),
                                  self.left.duty, self.right.duty)

# 主入口 主循环 2ms 调度

_loop = None
_led = None
_led_phase = 0.0

def _ticks_due(now, deadline):
    return time.ticks_diff(now, deadline) >= 0

def _led_step():
    global _led, _led_phase
    if _led is None:
        return
    duty = int((math.sin(_led_phase) + 1.0) / 2.0 * MOTOR_PWM_MAX)
    _led.duty_u16(duty)
    _led_phase += 0.02
    if _led_phase > 2.0 * math.pi:
        _led_phase -= 2.0 * math.pi

def main():
    global _loop, _led

    _led = PWM(Pin(LED_GPIO), freq=5000, duty=0)
    _loop = ControlLoop()

    gc.collect()
    print("wayTrack ready | pid=%s | kp=%.0f kd=%.0f | diff_gain=%.2f | base=%d" % (
          "on" if USE_ENCODER_SPEED_PID else "open",
          TRACK_CENTROID_KP, TRACK_CENTROID_KD,
          OPEN_LOOP_DIFF_GAIN, OPEN_LOOP_BASE_DUTY))
    print("running (startup delay: %d ms)" % (CTRL_STARTUP_DELAY * 2))

    next_ctrl = time.ticks_us()
    next_led = time.ticks_ms()
    try:
        while True:
            now_us = time.ticks_us()
            if _ticks_due(now_us, next_ctrl):
                _loop.step()
                next_ctrl = time.ticks_add(next_ctrl, CTRL_PERIOD_US)
                if time.ticks_diff(now_us, next_ctrl) > CTRL_PERIOD_US * 4:
                    next_ctrl = time.ticks_add(now_us, CTRL_PERIOD_US)

            now_ms = time.ticks_ms()
            if _ticks_due(now_ms, next_led):
                _led_step()
                next_led = time.ticks_add(next_led, 10)

            time.sleep_ms(0)
    except KeyboardInterrupt:
        _loop.motor.stop()
        _led.duty_u16(0)
        raise

main()
