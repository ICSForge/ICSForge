"""Entry point for `python -m icsforge.web`."""


def main() -> None:
    # Deferred import avoids the runpy 'found in sys.modules' warning that
    # occurs when Python has already partially imported the package.
    from icsforge.web.app import main as _main
    _main()


if __name__ == "__main__":
    main()
