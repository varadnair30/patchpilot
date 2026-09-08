from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_env = Environment(
    loader=FileSystemLoader(Path(__file__).resolve().parent.parent / "templates"),
    autoescape=select_autoescape(["html"]),
)


def render_receipt_email(user: dict, title: str, receipt: str) -> str:
    return _env.get_template("email.html").render(user=user, title=title, receipt=receipt)
