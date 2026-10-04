"""``python -m strix.eval <run_dir> <ground_truth.yaml>`` entry point."""

from strix.eval.harness import main


if __name__ == "__main__":
    raise SystemExit(main())
