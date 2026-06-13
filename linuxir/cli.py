"""Command-line entry point: ``linuxir analyze --case case.yaml [--offline]``."""

from __future__ import annotations

import argparse
import os
import sys

from . import corrections
from .config import CaseConfig
from .report import write_reports


def _run_analyze(args: argparse.Namespace) -> int:
    case = CaseConfig.from_yaml(args.case)
    max_iters = args.max_iterations or int(os.environ.get("MAX_ITERATIONS", "10"))

    if args.offline:
        from .agents.coordinator import Coordinator
        from .demo import demo_responder
        from .llm import FakeClient

        print(f"[offline] scripted demo client (no API calls) for case '{case.case_id}'")
        result = Coordinator(case, FakeClient(responder=demo_responder),
                             max_iterations=max_iters).run()

    elif args.auth == "subscription":
        # $0 path: Claude Agent SDK authenticated by your Pro/Max subscription.
        if os.environ.get("ANTHROPIC_API_KEY"):
            # The SDK silently prefers ANTHROPIC_API_KEY (billed) over the OAuth token —
            # drop it for this process so the subscription token is used.
            os.environ.pop("ANTHROPIC_API_KEY")
            print("[subscription] unset ANTHROPIC_API_KEY so the OAuth token is used.")
        if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            print("[warning] CLAUDE_CODE_OAUTH_TOKEN is not set. Run `claude setup-token` "
                  "on a machine with a browser and export it here, or `claude` login first.",
                  file=sys.stderr)
        from .agentsdk_runtime import SubscriptionRuntime

        print(f"[subscription] Claude Agent SDK (no API key / no per-token billing) "
              f"for case '{case.case_id}'")
        result = SubscriptionRuntime(case, model=args.model, effort=args.effort,
                                     max_iterations=max_iters).run()

    else:  # api
        from .agents.coordinator import Coordinator
        from .llm import get_client

        print(f"[api] Anthropic Messages API (billed) for case '{case.case_id}'")
        result = Coordinator(case, get_client(), max_iterations=max_iters).run()

    report_path, notes = write_reports(result)
    corrections.distill(result)

    print(f"\nCase:      {case.case_id}")
    print(f"Agents:    {', '.join(r.agent for r in result.agent_results)}")
    print(f"Findings:  {len(result.all_findings)} recorded, "
          f"{len(result.confirmed_findings)} confirmed, "
          f"{len(result.all_findings) - len(result.confirmed_findings)} dropped by auditor")
    review = sum(1 for f in result.confirmed_findings if f.requires_human_review)
    print(f"Review:    {review} confirmed findings flagged for human review")
    print(f"Correlations: {len(result.correlations)}")
    print("\nConfirmed findings:")
    for f in result.confirmed_findings:
        flag = " [review]" if f.requires_human_review else ""
        print(f"  - {f.short()}{flag}")
    print("\nOutput:")
    print(f"  report:  {report_path}")
    for n in notes:
        print(f"  note:    {n}")
    print(f"  audit:   {case.audit_dir / 'tool-calls.jsonl'}")
    print(f"  spoliation log: {case.audit_dir / 'spoliation-attempts.jsonl'}")
    
    _chat_loop(report_path, args)
    
    return 0


def _chat_loop(report_path, args: argparse.Namespace) -> None:
    if args.offline:
        return

    print("\n" + "="*60)
    print("Investigation complete. Entering interactive QA mode.")
    print("Type 'exit' or 'quit' to end the session.")
    print("="*60 + "\n")
    
    with open(report_path, "r", encoding="utf-8") as f:
        report_content = f.read()

    system_prompt = (
        "You are the Linux IR Agent. You have just completed an investigation. "
        "Here is the final executive report you generated:\n\n"
        f"{report_content}\n\n"
        "Please answer the user's questions strictly based on this report and the evidence it cites. "
        "If the answer is not in the report, state that you do not have that information. Keep your answers concise."
    )

    messages_api = []
    
    while True:
        try:
            user_input = input("User > ").strip()
            if user_input.lower() in ("exit", "quit"):
                break
            if not user_input:
                continue
            
            messages_api.append({"role": "user", "content": [{"type": "text", "text": user_input}]})
            print("Agent > ", end="", flush=True)
            
            if args.auth == "subscription":
                from claude_agent_sdk import ClaudeAgentOptions, query, ResultMessage
                import asyncio
                
                async def ask_agent():
                    options_kwargs = {
                        "system_prompt": system_prompt,
                        "allowed_tools": [],
                        "disallowed_tools": ["Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Task"],
                        "permission_mode": "bypassPermissions",
                        "setting_sources": None,
                        "max_turns": 1,
                    }
                    if getattr(args, "model", None):
                        options_kwargs["model"] = args.model
                    options = ClaudeAgentOptions(**options_kwargs)
                    final = ""
                    async for msg in query(prompt=messages_api, options=options):
                        if isinstance(msg, ResultMessage):
                            final = getattr(msg, "result", "") or final
                    return final
                    
                answer = asyncio.run(ask_agent())
            else:
                from .llm import get_client
                client = get_client()
                resp = client.messages.create(
                    model=getattr(args, "model", None) or "claude-3-5-sonnet-20241022",
                    system=system_prompt,
                    messages=messages_api,
                    max_tokens=2048,
                )
                answer = resp.content[0].text if resp.content else ""
                
            print(answer + "\n")
            messages_api.append({"role": "assistant", "content": [{"type": "text", "text": answer}]})
        except (KeyboardInterrupt, EOFError):
            print("\nExiting QA mode.")
            break


def _run_serve(args: argparse.Namespace) -> int:
    import uvicorn

    host = args.host or os.environ.get("LINUXIR_WEB_HOST", "127.0.0.1")
    port = args.port or int(os.environ.get("LINUXIR_WEB_PORT", "8080"))
    print(f"[web] LinuxIR Agent GUI on http://{host}:{port}  (Ctrl-C to stop)")
    uvicorn.run("linuxir.web.server:app", host=host, port=port, reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="linuxir",
        description="LinuxIR Agent — multi-agent Linux DFIR triage with architectural "
        "evidence-integrity guardrails.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Run an investigation against a case.")
    analyze.add_argument("--case", required=True, help="Path to a case YAML file.")
    analyze.add_argument(
        "--auth",
        choices=["subscription", "api"],
        default="subscription",
        help="subscription: Claude Agent SDK on your Pro/Max plan ($0 per-token, needs "
        "CLAUDE_CODE_OAUTH_TOKEN + the `claude` CLI). api: billed Messages API "
        "(needs ANTHROPIC_API_KEY). Default: subscription.",
    )
    analyze.add_argument(
        "--offline",
        action="store_true",
        help="Use the scripted demo client (no API calls / no key / no network).",
    )
    analyze.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        help="Cap orchestration iterations (default: $MAX_ITERATIONS or 10). The "
        "orchestrator degrades to a partial report rather than looping forever.",
    )
    analyze.add_argument(
        "--model",
        default=None,
        help="Model override (e.g. 'opus', 'sonnet'). Default: the plan/runtime default.",
    )
    analyze.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        default=None,
        help="Reasoning effort (subscription runtime only).",
    )
    analyze.set_defaults(func=_run_analyze)

    serve = sub.add_parser("serve", help="Launch the web GUI (FastAPI intake + status).")
    serve.add_argument("--host", default=None, help="Bind host (default 127.0.0.1 / LINUXIR_WEB_HOST).")
    serve.add_argument("--port", type=int, default=None, help="Bind port (default 8080 / LINUXIR_WEB_PORT).")
    serve.add_argument("--reload", action="store_true", help="Auto-reload on code changes (dev).")
    serve.set_defaults(func=_run_serve)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
