"""Entry point for running pencheff as a module: python -m pencheff"""

from pencheff.server import mcp


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
