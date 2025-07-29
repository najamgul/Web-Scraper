from flask import Blueprint, render_template, request
from .forms import InputForm
from . import vt_api, shodan_api, scraper, ml_model

main = Blueprint('main', __name__)

@main.route('/', methods=['GET', 'POST'])
def index():
    form = InputForm()
    results = {}
    error = None

    if form.validate_on_submit():
        user_input = form.input_data.data.strip()
        if not user_input:
            error = "Please enter a valid input"
        else:
            input_type = scraper.detect_input_type(user_input)
            scraped_data = []
            vt_result = {}
            shodan_result = {}
            prediction = "Unknown"

            if input_type == "keyword":
                # Use API instead of scraping Google
                urls = scraper.google_search_api(user_input)
                if not urls:
                    error = "No results found for the keyword"
                else:
                    for url in urls:
                        data = scraper.scrape_url(url)
                        if data:
                            scraped_data.append({
                                "url": url,
                                "content": data
                            })
            elif input_type in ["url", "ip", "hash"]:
                # Existing code for other input types
                try:
                    vt_result = vt_api.scan_with_virustotal(user_input)
                except Exception as e:
                    print(f"VirusTotal error: {e}")
                    
                try:
                    if input_type == "ip":
                        shodan_result = shodan_api.scan_with_shodan(user_input)
                except Exception as e:
                    print(f"Shodan error: {e}")
                    
                try:
                    prediction = ml_model.classify_threat(vt_result, shodan_result)
                except Exception as e:
                    print(f"Prediction error: {e}")

            results = {
                "input": user_input,
                "type": input_type,
                "vt": vt_result,
                "shodan": shodan_result,
                "scraped_data": scraped_data,
                "prediction": prediction
            }

            return render_template("results.html", results=results, error=error)

    return render_template("index.html", form=form, error=error)