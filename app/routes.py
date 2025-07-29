from flask import Blueprint, render_template, request
from .forms import InputForm
from . import vt_api, shodan_api, scraper, ml_model

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    form = InputForm()
    results = {}

    if form.validate_on_submit():
        user_input = form.input_data.data
        input_type = scraper.detect_input_type(user_input)

        scraped_data = []
        vt_result = {}
        shodan_result = {}
        prediction = "Unknown"

        if input_type == "keyword":
            urls = scraper.google_dorking(user_input)
            for url in urls:
                scraped_data.append(scraper.scrape_url(url))
        elif input_type in ["url", "ip"]:
            vt_result = vt_api.scan_with_virustotal(user_input)
            shodan_result = shodan_api.scan_with_shodan(user_input)
            prediction = ml_model.classify_threat(vt_result, shodan_result)

        results = {
            "input": user_input,
            "type": input_type,
            "vt": vt_result,
            "shodan": shodan_result,
            "scraped_data": scraped_data,
            "prediction": prediction
        }

        return render_template("results.html", results=results)

    return render_template("index.html", form=form)
