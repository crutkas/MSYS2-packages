#!/usr/bin/env python3
from __future__ import annotations

import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


OLD_LINE = '    if $cc -o try $flag $ccflags $ldflags try.c 2>/dev/null && ./try; then'
NEW_LINE = '    if $cc -o try.exe $flag $ccflags $ldflags try.c 2>/dev/null; then'

OLD_BLOCK = """c99_for=no
for flag in '' '-std=gnu99' '-std=c99'; do
    if $cc -o try $flag $ccflags $ldflags try.c 2>/dev/null && ./try; then
        c99_for="$flag"
        break;
    fi
done
case "$c99_for" in
'') echo "Your C compiler doesn't need any special flags to compile C99 code"
    ;;
no) echo "Your C compiler doesn't seem to be able to compile C99 code"
    rp='Do you really want to continue?'
    dflt='n'
    . ./myread
    case "$ans" in
        [yY]) echo >&4 "Okay, continuing." ;;
        *) exit 1 ;;
    esac
    ;;
*)  echo "Your C compiler needs $c99_for to compile C99 code"
    ;;
esac"""

NEW_BLOCK = """c99_for=no
for flag in '' '-std=gnu99' '-std=c99'; do
    if $cc -o try.exe $flag $ccflags $ldflags try.c 2>/dev/null; then
        c99_for="$flag"
        break;
    fi
done
case "$c99_for" in
'') echo "Your C compiler doesn't need any special flags to compile C99 code"
    ;;
no) echo "Your C compiler doesn't seem to be able to compile C99 code"
    rp='Do you really want to continue?'
    dflt='n'
    . ./myread
    case "$ans" in
        [yY]) echo >&4 "Okay, continuing." ;;
        *) exit 1 ;;
    esac
    ;;
*)  echo "Your C compiler needs $c99_for to compile C99 code"
    ;;
esac"""


def rewrite_configure(text: str) -> str:
    old_count = text.count(OLD_LINE)
    new_count = text.count(NEW_LINE)
    if old_count + new_count != 1:
        raise AssertionError(
            f"expected exactly one C99 probe line, saw old={old_count} new={new_count}"
        )
    if old_count == 1:
        return text.replace(OLD_LINE, NEW_LINE, 1)
    return text


def assert_recipe_anchor() -> None:
    recipe = (REPO_ROOT / "perl/PKGBUILD").read_text(encoding="utf-8")
    expected_fragments = [
        'my $old = q{    if $cc -o try $flag $ccflags $ldflags try.c 2>/dev/null && ./try; then};',
        'my $new = q{    if $cc -o try.exe $flag $ccflags $ldflags try.c 2>/dev/null; then};',
        'my $old_count = () = /\\Q$old\\E/g;',
        'my $new_count = () = /\\Q$new\\E/g;',
        'die "unexpected ARM64 C99 probe text\\n" if $old_count + $new_count != 1;',
        's/\\Q$old\\E/$new/ or die "expected ARM64 C99 probe rewrite failed\\n";',
    ]
    for fragment in expected_fragments:
        assert fragment in recipe, f"missing narrow rewrite fragment: {fragment}"
    assert "c99_for=no.*?" not in recipe, "broad Configure block rewrite still present"
    assert "c99_for=''; echo" not in recipe, "silently no-op Configure rewrite still present"


def assert_rewrite_behaviour() -> None:
    cases = [
        ("original fixture", f"before\n{OLD_BLOCK}\nafter\n", f"before\n{NEW_BLOCK}\nafter\n"),
        ("expected fixture", f"before\n{NEW_BLOCK}\nafter\n", f"before\n{NEW_BLOCK}\nafter\n"),
        ("already-applied fixture", f"prefix\n{NEW_BLOCK}\nsuffix\n", f"prefix\n{NEW_BLOCK}\nsuffix\n"),
        ("unrelated text", "prefix\nno probe here\nsuffix\n", None),
    ]
    for name, fixture, expected in cases:
        if expected is None:
            try:
                rewrite_configure(fixture)
            except AssertionError:
                pass
            else:
                raise AssertionError(f"{name} must fail closed when the probe text is absent")
            continue
        rewritten = rewrite_configure(fixture)
        assert rewritten == expected, f"{name} changed more than the probe line"
        assert rewrite_configure(rewritten) == rewritten, f"{name} is not idempotent"

    for name, fixture in [
        ("missing fixture", "before\nmissing\nafter\n"),
        ("duplicate original fixture", f"{OLD_LINE}\n{OLD_LINE}\n"),
        ("duplicate expected fixture", f"{NEW_LINE}\n{NEW_LINE}\n"),
    ]:
        try:
            rewrite_configure(fixture)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"rewrite must fail closed for {name}")


def resolve_probe_aliases(output_name: str, directory: Path) -> tuple[bool, bool]:
    source = None
    for candidate in (output_name, f"{output_name}.exe", f"{output_name}.exe.exe"):
        candidate_path = directory / candidate
        if candidate_path.is_file():
            source = candidate_path
            break
    if source is None:
        return False, False
    (directory / "try.exe").write_bytes(source.read_bytes())
    (directory / "try").write_text(
        "#!/bin/sh\nexec \"$PWD/try.exe\" \"$@\"\n",
        encoding="ascii",
    )
    return (directory / "try").is_file(), (directory / "try.exe").is_file()


def assert_suffix_behaviour() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for output_name in ("try", "try.exe", "try.exe.exe"):
            for candidate in ("try", "try.exe", "try.exe.exe"):
                path = tmpdir / candidate
                if path.exists():
                    path.unlink()
            (tmpdir / output_name).write_text("probe", encoding="ascii")
            got_try, got_try_exe = resolve_probe_aliases(output_name, tmpdir)
            assert got_try and got_try_exe, f"wrapper failed to alias {output_name}"
            assert (tmpdir / "try").read_text(encoding="ascii") == (
                "#!/bin/sh\nexec \"$PWD/try.exe\" \"$@\"\n"
            ), f"wrapper shim content changed for {output_name}"
            assert (tmpdir / "try.exe").read_text(encoding="ascii") == "probe"


def main() -> None:
    assert_recipe_anchor()
    assert_rewrite_behaviour()
    assert_suffix_behaviour()
    print("perl arm64 configure probe tests passed")


if __name__ == "__main__":
    main()
