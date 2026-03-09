from strix.telemetry.utils import prune_otel_span_attributes


def test_prune_otel_span_attributes_drops_high_volume_prompt_content() -> None:
    attributes = {
        "gen_ai.operation.name": "openai.chat",
        "gen_ai.request.model": "gpt-5.2",
        "gen_ai.prompt.0.role": "system",
        "gen_ai.prompt.0.content": "a" * 20_000,
        "gen_ai.completion.0.content": "b" * 10_000,
        "llm.input_messages.0.content": "c" * 5_000,
        "llm.output_messages.0.content": "d" * 5_000,
        "llm.input": "x" * 3_000,
        "llm.output": "y" * 3_000,
    }

    pruned = prune_otel_span_attributes(attributes)

    assert "gen_ai.prompt.0.content" not in pruned
    assert "gen_ai.completion.0.content" not in pruned
    assert "llm.input_messages.0.content" not in pruned
    assert "llm.output_messages.0.content" not in pruned
    assert "llm.input" not in pruned
    assert "llm.output" not in pruned
    assert pruned["gen_ai.operation.name"] == "openai.chat"
    assert pruned["gen_ai.prompt.0.role"] == "system"
    assert pruned["strix.filtered_attributes_count"] == 6


def test_prune_otel_span_attributes_keeps_metadata_when_nothing_is_dropped() -> None:
    attributes = {
        "gen_ai.operation.name": "openai.chat",
        "gen_ai.request.model": "gpt-5.2",
        "gen_ai.prompt.0.role": "user",
    }

    pruned = prune_otel_span_attributes(attributes)

    assert pruned == attributes
