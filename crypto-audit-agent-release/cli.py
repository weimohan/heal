
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptoaudit.agent import AgentOrchestrator
from cryptoaudit.baseline import BaselineRunner
from cryptoaudit.contracts import AuditSession
from cryptoaudit.provider import OfflineProvider, OpenAIProvider
from cryptoaudit.services import compare_sessions, render_markdown, result_json, save_checkpoint


ROOT = Path(__file__).resolve().parent
KNOWLEDGE = ROOT / "knowledge" / "cards.jsonl"


def _write_session(session: AuditSession, output_dir: Path, state_dir: Path | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit_run.json").write_text(result_json(session), encoding="utf-8")
    (output_dir / "audit_report.md").write_text(render_markdown(session), encoding="utf-8")
    if state_dir:
        save_checkpoint(session, state_dir)


def _agent_provider(args: argparse.Namespace):
    key = (args.api_key or os.environ.get("OPENAI_API_KEY", "")).strip()
    if key:
        if not args.allow_source:
            raise ValueError("GPT mode requires --allow-source before source submission")
        return OpenAIProvider(key, model=args.model, timeout_seconds=args.timeout)
    return OfflineProvider()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CryptoAudit Agent release")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("baseline", "agent"):
        command = sub.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("--output-dir", type=Path, default=Path("runtime/audit"))
        command.add_argument("--state-dir", type=Path, default=None)
        command.add_argument("--task-id", default=None)
        if name == "agent":
            command.add_argument("--api-key", default=None)
            command.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-5-mini"))
            command.add_argument("--timeout", type=int, default=30)
            command.add_argument("--allow-source", action="store_true")
    compare = sub.add_parser("compare")
    compare.add_argument("source", type=Path)
    compare.add_argument("--output-dir", type=Path, default=Path("runtime/compare"))
    compare.add_argument("--api-key", default=None)
    compare.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-5-mini"))
    compare.add_argument("--timeout", type=int, default=30)
    compare.add_argument("--allow-source", action="store_true")
    evaluation = sub.add_parser("eval")
    evaluation.add_argument("--dataset", type=Path, default=ROOT / "evals" / "dataset.json")
    evaluation.add_argument("--mode", choices=("baseline", "agent"), default="baseline")
    evaluation.add_argument("--output", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "baseline":
        source = args.source.read_text(encoding="utf-8")
        session = BaselineRunner(KNOWLEDGE).run(source, source_name=args.source.name, task_id=args.task_id)
        _write_session(session, args.output_dir, args.state_dir)
        print(render_markdown(session))
        return 0
    if args.command == "agent":
        source = args.source.read_text(encoding="utf-8")
        session = AuditSession.from_source(source, source_name=args.source.name, task_id=args.task_id, mode="agent")
        session = AgentOrchestrator(provider=_agent_provider(args), knowledge_path=KNOWLEDGE, max_steps=12).start(session)
        _write_session(session, args.output_dir, args.state_dir)
        print(render_markdown(session))
        return 0
    if args.command == "compare":
        source = args.source.read_text(encoding="utf-8")
        baseline = BaselineRunner(KNOWLEDGE).run(source, source_name=args.source.name, task_id="baseline-" + args.source.stem)
        agent = AgentOrchestrator(provider=_agent_provider(args), knowledge_path=KNOWLEDGE, max_steps=12).start(
            AuditSession.from_source(source, source_name=args.source.name, task_id="agent-" + args.source.stem, mode="agent")
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "baseline.json").write_text(result_json(baseline), encoding="utf-8")
        (args.output_dir / "agent.json").write_text(result_json(agent), encoding="utf-8")
        (args.output_dir / "comparison.json").write_text(json.dumps(compare_sessions(baseline, agent), ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(compare_sessions(baseline, agent), ensure_ascii=False, indent=2))
        return 0
    from evals.runner import evaluate_dataset

    result = evaluate_dataset(args.dataset, mode=args.mode)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
