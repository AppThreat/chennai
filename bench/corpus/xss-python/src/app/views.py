from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/search")
def search():
    """Search endpoint that reflects user input without escaping."""
    query = request.args.get("q", "")
    # VULNERABLE: using |safe filter bypasses Jinja2 auto-escaping
    html = render_template_string(
        "<h1>Search Results</h1>"
        "<p>You searched for: {{ query|safe }}</p>"  # line 15
    )
    return html

@app.route("/safe_search")
def safe_search():
    """Safe version: Jinja2 auto-escaping is enabled by default."""
    query = request.args.get("q", "")
    return render_template_string(
        "<h1>Search Results</h1>"
        "<p>You searched for: {{ query }}</p>"
    )
