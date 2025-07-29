from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import pandas as pd
import time

def scrape_data():
    print("Starting scraping...")

    # Setup Chrome driver
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_driver_path = r"D:\chromedriver-win64\chromedriver.exe"
    service = Service(executable_path=chrome_driver_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)

    # Go to BBC News
    driver.get('https://www.bbc.com/news')
    time.sleep(2)

    # Scrape headlines
    elements = driver.find_elements(By.CSS_SELECTOR, 'h2')
    headlines = [e.text.strip() for e in elements if e.text.strip()]

    # Save to CSV
    if headlines:
        df = pd.DataFrame(set(headlines), columns=['Headline'])
        df.to_csv("headlines.csv", index=False)
        print("Saved to headlines.csv")
    else:
        print("No headlines found.")

    driver.quit()

# Run the function
if __name__ == "__main__":
    scrape_data()
