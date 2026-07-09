from machine import ADC, Pin, PWM, Timer, Encoder
import time

# ===================== 引脚配置 =====================

ADC_PINS = [27, 33, 32, 35, 34]

M1_IN1_PIN = 13
M1_IN2_PIN = 15
M2_IN1_PIN = 14
M2_IN2_PIN = 25

PWM_FREQ = 20000

MOTOR1_REVERSE = False
MOTOR2_REVERSE = True

# ===================== Encoder 配置 =====================

USE_ENCODER_INNER_PID = True

encoder_L = Encoder(0, Pin(17, Pin.IN), Pin(16, Pin.IN))
encoder_R = Encoder(1, Pin(18, Pin.IN), Pin(19, Pin.IN))

ENC_LEFT_REVERSE = False
ENC_RIGHT_REVERSE = False

PULSES_PER_SECOND_AT_100 = 91688.5    # 100%输出时编码器每秒脉冲数，需实测标定

# ===================== 循迹参数 =====================

LINE_THRESHOLD = 80
WEIGHTS = [-4, -1, 0, 1, 4]

BASE_SPEED = 68                      # 单位：百分比速度，不是PWM；允许大于100，但最终会按标定换算成编码器目标脉冲速度
MAX_SPEED = 100                       # 100%速度对应 PULSES_PER_SECOND_AT_100
LOST_TURN_SPEED = 75


KEEP_LAST_ACTION_WHEN_LOST = 0 #丢线后动作
LOST_ACTION_SCALE = 1.0
LOST_ACTION_MAX_MS = 800
LOST_ACTION_SAFE_SPEED = 35

# 外环 PID
KP = 16.0
KI = 0.0
KD = 16.0

CORRECTION_LIMIT = 100 #最大允许修正量


# 内环轮速 PID
INNER_KP = 0.75
INNER_KI = 0.08
INNER_KD = 0.02
INNER_INTEGRAL_LIMIT = 100.0

CONTROL_PERIOD_MS = 20
DEBUG_PRINT = True

# ===================== 硬件初始化 =====================

adcs = []
for pin_num in ADC_PINS:
    adc = ADC(Pin(pin_num))
    adc.atten(ADC.ATTN_11DB)
    adc.width(ADC.WIDTH_12BIT)
    adcs.append(adc)

pwm_m1_in1 = PWM(Pin(M1_IN1_PIN), freq=PWM_FREQ, duty=0)
pwm_m1_in2 = PWM(Pin(M1_IN2_PIN), freq=PWM_FREQ, duty=0)
pwm_m2_in1 = PWM(Pin(M2_IN1_PIN), freq=PWM_FREQ, duty=0)
pwm_m2_in2 = PWM(Pin(M2_IN2_PIN), freq=PWM_FREQ, duty=0)

# ===================== 全局状态 =====================

control_flag = False

last_error = 0.0
integral = 0.0

left_inner_integral = 0.0
right_inner_integral = 0.0
left_inner_last_error = 0.0
right_inner_last_error = 0.0

last_left_target = BASE_SPEED
last_right_target = BASE_SPEED
last_action_valid = False
lost_start_time = None

left_measured_speed = 0.0
right_measured_speed = 0.0


# ===================== 工具函数 =====================

def clamp(value, low, high):
    if value < low:
        return low
    if value > high:
        return high
    return value


def speed_percent_to_encoder_speed(speed_percent):
    """
    把“百分比速度”转换成“每个控制周期的编码器目标脉冲数”。

    PULSES_PER_SECOND_AT_100 表示 100%输出时，每秒编码器脉冲数。
    CONTROL_PERIOD_MS=20 时：
    100%目标速度 = 90000 * 20 / 1000 = 1800 脉冲/周期

    所以 BASE_SPEED=300 表示 300%目标速度：
    目标 = 90000 * 3.0 * 20 / 1000 = 5400 脉冲/周期

    注意：这里不再把 300 限制成 100。
    """
    return speed_percent * PULSES_PER_SECOND_AT_100 * CONTROL_PERIOD_MS / 100000.0


def pwm_percent_to_duty(pwm_percent):
    """
    把内环PID输出的PWM百分比转换成PWM duty。
    只有最终给PWM硬件时才限制到 -100~100。
    """
    pwm_percent = clamp(pwm_percent, -100, 100)
    return int(abs(pwm_percent) * 1023 / 100)


def apply_motor_reverse(speed, reverse):
    if reverse:
        return -speed
    return speed


def set_motor1_pwm(pwm_percent):
    pwm_percent = apply_motor_reverse(pwm_percent, MOTOR1_REVERSE)
    duty = pwm_percent_to_duty(pwm_percent)

    if pwm_percent > 0:
        pwm_m1_in1.duty(duty)
        pwm_m1_in2.duty(0)
    elif pwm_percent < 0:
        pwm_m1_in1.duty(0)
        pwm_m1_in2.duty(duty)
    else:
        pwm_m1_in1.duty(0)
        pwm_m1_in2.duty(0)


def set_motor2_pwm(pwm_percent):
    pwm_percent = apply_motor_reverse(pwm_percent, MOTOR2_REVERSE)
    duty = pwm_percent_to_duty(pwm_percent)

    if pwm_percent > 0:
        pwm_m2_in1.duty(duty)
        pwm_m2_in2.duty(0)
    elif pwm_percent < 0:
        pwm_m2_in1.duty(0)
        pwm_m2_in2.duty(duty)
    else:
        pwm_m2_in1.duty(0)
        pwm_m2_in2.duty(0)


def set_motor(left_pwm_percent, right_pwm_percent):
    set_motor1_pwm(left_pwm_percent)
    set_motor2_pwm(right_pwm_percent)


def stop():
    set_motor(0, 0)


# ===================== 定时器中断 =====================

def TIMER_IRQHandler(tim):
    global control_flag
    control_flag = True


timer = Timer(1)
timer.init(period=CONTROL_PERIOD_MS, mode=Timer.PERIODIC, callback=TIMER_IRQHandler)


# ===================== ADC 循迹 =====================

def read_adc_values():
    return [adc.read() for adc in adcs]


def read_line_error():
    raw_values = read_adc_values()

    strengths = []
    active = []

    for value in raw_values:
        strength = value - LINE_THRESHOLD

        if strength > 0:
            strengths.append(strength)
            active.append(1)
        else:
            strengths.append(0)
            active.append(0)

    strength_sum = sum(strengths)

    if strength_sum <= 0:
        return None, raw_values, active

    weighted_sum = 0.0

    for i in range(5):
        weighted_sum += WEIGHTS[i] * strengths[i]

    error = weighted_sum / strength_sum

    return error, raw_values, active


# ===================== 外环 PID =====================

def outer_pid_output(error):
    global last_error, integral

    integral += error
    integral = clamp(integral, -20, 20)

    derivative = error - last_error
    last_error = error

    correction = KP * error + KI * integral + KD * derivative
    correction = clamp(correction, -CORRECTION_LIMIT, CORRECTION_LIMIT)

    return correction


# ===================== Encoder 测速 =====================

def update_measured_wheel_speed(dt_ms):
    global left_measured_speed, right_measured_speed

    if not USE_ENCODER_INNER_PID:
        left_measured_speed = 0.0
        right_measured_speed = 0.0
        return left_measured_speed, right_measured_speed

    left_counts = encoder_L.value()
    right_counts = encoder_R.value()

    encoder_L.value(0)
    encoder_R.value(0)

    if ENC_LEFT_REVERSE:
        left_counts = -left_counts
    if ENC_RIGHT_REVERSE:
        right_counts = -right_counts

    # 这里改成“每个控制周期的编码器脉冲数”
    # 不再换算成0~100百分比，否则会和 PULSES_PER_SECOND_AT_100 重复缩放
    left_measured_speed = float(left_counts)
    right_measured_speed = float(right_counts)

    return left_measured_speed, right_measured_speed


# ===================== 内环 PID =====================

def inner_speed_pid(target_speed, measured_speed, side):
    """
    target_speed / measured_speed：编码器脉冲数/控制周期
    返回值 command：PWM百分比，最终由 set_motor 转成 0~1023 duty
    """
    global left_inner_integral, right_inner_integral
    global left_inner_last_error, right_inner_last_error

    if abs(target_speed) < 1:
        if side == "left":
            left_inner_integral = 0.0
            left_inner_last_error = 0.0
        else:
            right_inner_integral = 0.0
            right_inner_last_error = 0.0
        return 0.0

    error = target_speed - measured_speed

    if side == "left":
        left_inner_integral += error
        left_inner_integral = clamp(
            left_inner_integral,
            -INNER_INTEGRAL_LIMIT,
            INNER_INTEGRAL_LIMIT
        )
        derivative = error - left_inner_last_error
        left_inner_last_error = error

        command = (
            INNER_KP * error
            + INNER_KI * left_inner_integral
            + INNER_KD * derivative
        )

    else:
        right_inner_integral += error
        right_inner_integral = clamp(
            right_inner_integral,
            -INNER_INTEGRAL_LIMIT,
            INNER_INTEGRAL_LIMIT
        )
        derivative = error - right_inner_last_error
        right_inner_last_error = error

        command = (
            INNER_KP * error
            + INNER_KI * right_inner_integral
            + INNER_KD * derivative
        )

    command = clamp(command, -100, 100)

    return command


def apply_inner_speed_control(left_target, right_target):
    if USE_ENCODER_INNER_PID:
        left_cmd = inner_speed_pid(left_target, left_measured_speed, "left")
        right_cmd = inner_speed_pid(right_target, right_measured_speed, "right")
    else:
        # 不用内环时，直接把目标速度百分比当作PWM百分比输出
        left_cmd = left_target
        right_cmd = right_target

    left_cmd = clamp(left_cmd, -100, 100)
    right_cmd = clamp(right_cmd, -100, 100)

    set_motor(left_cmd, right_cmd)

    return left_cmd, right_cmd


# ===================== 丢线处理 =====================

def get_lost_line_action():
    global lost_start_time

    now = time.ticks_ms()

    if lost_start_time is None:
        lost_start_time = now

    if KEEP_LAST_ACTION_WHEN_LOST and last_action_valid:
        left_target = last_left_target * LOST_ACTION_SCALE
        right_target = last_right_target * LOST_ACTION_SCALE

        if time.ticks_diff(now, lost_start_time) > LOST_ACTION_MAX_MS:
            safe_target = speed_percent_to_encoder_speed(LOST_ACTION_SAFE_SPEED)
            left_target = clamp(left_target, -safe_target, safe_target)
            right_target = clamp(right_target, -safe_target, safe_target)

        return left_target, right_target

    turn_target = speed_percent_to_encoder_speed(LOST_TURN_SPEED)

    if last_error < 0:
        return -turn_target, turn_target

    if last_error > 0:
        return turn_target, -turn_target

    forward_target = speed_percent_to_encoder_speed(BASE_SPEED)
    return forward_target, forward_target


# ===================== 单次循迹控制 =====================

def line_follow_step(dt_ms):
    global last_left_target, last_right_target
    global last_action_valid, lost_start_time

    update_measured_wheel_speed(dt_ms)

    error, raw_values, active = read_line_error()

    if error is None:
        left_target, right_target = get_lost_line_action()
        left_cmd, right_cmd = apply_inner_speed_control(left_target, right_target)

        return (
            raw_values,
            active,
            None,
            0,
            left_target,
            right_target,
            left_cmd,
            right_cmd,
            True
        )

    lost_start_time = None

    correction_percent = outer_pid_output(error)

    # 外环仍然按“百分比速度”修正，然后统一换算成编码器目标速度
    left_target_percent = BASE_SPEED + correction_percent
    right_target_percent = BASE_SPEED - correction_percent

    left_target = speed_percent_to_encoder_speed(left_target_percent)
    right_target = speed_percent_to_encoder_speed(right_target_percent)

    last_left_target = left_target
    last_right_target = right_target
    last_action_valid = True

    left_cmd, right_cmd = apply_inner_speed_control(left_target, right_target)

    return (
        raw_values,
        active,
        error,
        correction_percent,
        left_target,
        right_target,
        left_cmd,
        right_cmd,
        False
    )


# ===================== 主程序 =====================

def main():
    global control_flag

    print("ESP32 5ADC line follower started")
    print("Encoder uses machine.Encoder")
    print("Timer interrupt only sets control_flag")
    print("ADC pins:", ADC_PINS)
    print("Motor1 PWM pins:", M1_IN1_PIN, M1_IN2_PIN)
    print("Motor2 PWM pins:", M2_IN1_PIN, M2_IN2_PIN)
    print("Black line condition: ADC >=", LINE_THRESHOLD)
    print("Weights:", WEIGHTS)
    print("BASE_SPEED percent:", BASE_SPEED)
    print("PULSES_PER_SECOND_AT_100:", PULSES_PER_SECOND_AT_100)
    print("100 percent target per period:", speed_percent_to_encoder_speed(100))
    print("BASE target per period:", speed_percent_to_encoder_speed(BASE_SPEED))
    print("LOST_TURN_SPEED percent:", LOST_TURN_SPEED)

    last_time = time.ticks_ms()

    try:
        while True:
            if control_flag:
                control_flag = False

                now = time.ticks_ms()
                dt_ms = time.ticks_diff(now, last_time)
                last_time = now

                raw, active, error, correction, lt, rt, lc, rc, lost = line_follow_step(dt_ms)

                if DEBUG_PRINT:
                    print(
                        "raw:", raw,
                        "line:", active,
                        "err:", error,
                        "corr_percent:", round(correction, 2),
                        "target_count:", [round(lt, 1), round(rt, 1)],
                        "meas_count:", [
                            round(left_measured_speed, 1),
                            round(right_measured_speed, 1)
                        ],
                        "pwm_percent:", [round(lc, 1), round(rc, 1)],
                        "lost:", lost
                    )

            time.sleep_ms(1)

    except KeyboardInterrupt:
        stop()
        timer.deinit()
        pwm_m1_in1.deinit()
        pwm_m1_in2.deinit()
        pwm_m2_in1.deinit()
        pwm_m2_in2.deinit()
        print("Stopped")


if __name__ == "__main__":
    main()





