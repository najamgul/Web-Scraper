from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import random
from nltk.corpus import stopwords
from collections import Counter
from textblob import TextBlob
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation
import nltk
import os

# Ensure NLTK stopwords are available
nltk.download('stopwords')

app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def display_topics(model, feature_names, no_top_words):
    topics = []
    for topic_idx, topic in enumerate(model.components_):
        topics.append([feature_names[i] for i in topic.argsort()[:-no_top_words - 1:-1]])
    return topics

@app.route('/')
def index():
    df = pd.read_csv('headlines.csv')
    headlines = df['Headline'].dropna().str.lower()
    
    stop_words = set(stopwords.words('english'))
    words = ' '.join(headlines).split()
    words = [word for word in words if word not in stop_words and word != 'watch']
    
    word_counts = Counter(words)
    top_n_words = word_counts.most_common(10)
    phrase_words = random.sample([word for word, _ in top_n_words], random.randint(1, min(5, len(top_n_words))))
    phrase = ' '.join(phrase_words)

    df['Sentiment'] = df['Headline'].apply(lambda x: TextBlob(x).sentiment.polarity)
    sentiment_counts = df['Sentiment'].apply(lambda x: 'Positive' if x > 0 else 'Negative' if x < 0 else 'Neutral').value_counts()
    
    vectorizer = CountVectorizer(stop_words='english')
    X = vectorizer.fit_transform(headlines)
    lda = LatentDirichletAllocation(n_components=5, random_state=42)
    lda.fit(X)
    topics = display_topics(lda, vectorizer.get_feature_names_out(), 5)
    
    return render_template('index.html', phrase=phrase, topics=topics, sentiment_counts=sentiment_counts.to_dict(), top_n_words=top_n_words)

@app.route('/upload', methods=['POST'])
def upload():
    text_data = request.form.get('text')
    image = request.files.get('image')

    if text_data:
        with open('static/uploads/input_text.txt', 'w', encoding='utf-8') as f:
            f.write(text_data)

    if image:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.filename)
        image.save(image_path)

    print("Uploaded Text:", text_data)
    print("Image saved:", image.filename if image else "No Image")

    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    text = None
    image = None

    if request.method == 'POST':
        text = request.form.get('text_input')
        image = request.files.get('image_input')

        if image:
            image.save('static/uploaded.png')  # Save image to static folder
            image = 'uploaded.png'  # Path to show in HTML

    return render_template('index.html', text=text, image=image)

if __name__ == '__main__':
    app.run(debug=True)
