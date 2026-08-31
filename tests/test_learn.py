"""Tests for the student-facing `learn` command."""

import pytest

import tool


def test_every_topic_is_well_formed():
    for key, data in tool.LEARN_TOPICS.items():
        assert data["title"]
        assert data["summary"]
        assert data["points"] and all(isinstance(p, str) for p in data["points"])
        assert data["commands"]
        assert data["reading"]


def test_learn_topics_returns_all_when_unfiltered(capsys):
    results = tool.learn_topics(None)
    assert {r["topic"] for r in results} == set(tool.LEARN_TOPICS)
    assert "Learn:" in capsys.readouterr().out


def test_learn_topics_filters_to_one(capsys):
    results = tool.learn_topics("recon")
    assert [r["topic"] for r in results] == ["recon"]
    assert "Reconnaissance" in capsys.readouterr().out


def test_learn_topics_rejects_unknown():
    with pytest.raises(ValueError):
        tool.learn_topics("not-a-topic")


def test_referenced_commands_exist_in_parser():
    parser = tool.build_parser()
    choices = set()
    for action in parser._actions:
        if getattr(action, "choices", None) and action.dest == "command":
            choices = set(action.choices)
            break
    for data in tool.LEARN_TOPICS.values():
        for command in data["commands"]:
            assert command in choices, f"learn references unknown command: {command}"


def test_cli_parses_learn_command():
    args = tool.build_parser().parse_args(["learn", "web"])
    assert args.command == "learn"
    assert args.topic == "web"
