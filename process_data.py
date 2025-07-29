import pandas as pd
import matplotlib.pyplot as plt
from wordcloud import WordCloud
from textblob import TextBlob
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.decomposition import LatentDirichletAllocation
from nltk.corpus import stopwords
from collections import Counter
import nltk

nltk.download('stopwords')
df = pd.read_csv('headlines.csv')
headlines = df['Headline'].dropna().str.lower()

stop_words = set(stopwords.words('english'))
words = ' '.join(headlines).split()
words = [word for word in words if word not in stop_words and word != 'watch']
word_counts = Counter(words)
top_n_words = word_counts.most_common(10)

df['Sentiment'] = df['Headline'].apply(lambda x: TextBlob(x).sentiment.polarity)
sentiment_counts = df['Sentiment'].apply(lambda x: 'Positive' if x > 0 else 'Negative' if x < 0 else 'Neutral').value_counts()

# Bar Plot
plt.figure(figsize=(10, 6))
plt.bar([word for word, _ in top_n_words], [count for _, count in top_n_words], color='skyblue')
plt.xticks(rotation=45)
plt.title('Top 10 Most Frequent Words')
plt.tight_layout()
plt.savefig('static/word_plot.png', format='png')

# WordCloud
wordcloud = WordCloud(width=800, height=400, background_color='white').generate_from_frequencies(dict(top_n_words))
plt.figure(figsize=(10, 6))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis('off')
plt.tight_layout()
plt.savefig('static/wordcloud.png', format='png')
