import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib import style
import seaborn as sns
sns.set_style('whitegrid')
# import tensorflow as tf
from sklearn.model_selection import train_test_split, cross_val_predict
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score
import time
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
# %matplotlib inline

SMALL_SIZE = 10
MEDIUM_SIZE = 12

sdss_df = pd.read_csv('Training_data.csv', skiprows=0)

sdss_df.drop(['url', 'Domain', 'whois_country'], axis=1, inplace=True)

X= sdss_df.iloc[:, 1:-1 ].values
y= sdss_df.iloc[:, -1].values
X.shape

# import seaborn as sns
# import matplotlib.pyplot as plt  # Import matplotlib for figure size

# Reading a dataset (Assuming sdss_df is your dataset)
givenDataset = sdss_df

# Assigning the list of columns from the dataset
numericColumns = ['Have_At', 'URL_Length', 'URL_Depth',
       'Redirection', 'https_Domain', 'Prefix/Suffix', 'iFrame',
       'Mouse_Over', 'Right_Click', 'Web_Forwards',
       'count_special_characters', 'content_length', 'subdomain_count',
       'tinyURL', 'favicon_presence',
       'Domain_registratioin_length', 'TopLevelDomain',
       'Lexical_analysis', 'check_hyphens', 'status_code', 'Label']

# Creating a correlation matrix
correlationMatrix = givenDataset.loc[:, numericColumns].corr()

# Set the figure size for the heatmap
# plt.figure(figsize=(12, 10))  # You can adjust the width and height as needed

# # Displaying the correlation matrix as a heatmap
# sns.heatmap(correlationMatrix, annot=True)

# # Show the plot
# plt.show()

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33)

from urllib.parse import urlparse, urlencode
import ipaddress
import re
import requests
import whois
from datetime import datetime
from bs4 import BeautifulSoup

# 1.Domain of the URL
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.",domain):
        domain = domain.replace("www.","")
    return domain


# 2.Checks for IP address in URL
def havingIP(url):
    # Regular expression pattern to match an IPv4 address
    ipv4_pattern = r"\b(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\." \
                   r"(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\." \
                   r"(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\." \
                   r"(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\b"

    # Check if the URL contains an IPv4 address in its hostname
    if re.search(ipv4_pattern, url):
        return 1  # IP address is present
    else:
        return 0   # IP address is absent, safe website


# 3.Checks the presence of @ in URL
def haveAtSign(url):
  if "@" in url:
    return 1
  else:
    return 0


# 4.Finding the length of URL
def getLength(url):
  if len(url) < 54:
    return 0
  else:
    return 1


#5 def getDepth(url):
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth


# 6.Checking for redirection '//' in the url
def redirection(url):
    try:
        response = requests.get(url, allow_redirects=True)
        redirection_chain = [url] + [redirect.url for redirect in response.history]

        for redirect_url in redirection_chain:
            if url != redirect_url and url.split('//')[1] != redirect_url.split('//')[1]:
                return 1 # Phishing website detected due to suspicious redirection

        return 0    #Safe website - no suspicious redirection found

    except requests.RequestException as e:
        return -1  # Error occurred during URL fetch'


# 7.Existence of “HTTPS” domain
def httpDomain(url):
    try:
        # Check if the URL starts with "https://"
        if url.startswith("https://"):
            return 0  # Safe website
        else:
            return 1  # Phishing website

    except Exception as e:
        return -1  # Error occurred during processing



# 8.Checking (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1
    else:
        return 0


#9 IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[|]", response.text):
          return 0
      else:
          return 1

#10 Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check if the HTML contains JavaScript for mouse-over events
        javascript_code = soup.find('script')

        if javascript_code and 'onmouseover' in javascript_code.text:
            return 1  # Potentially phishing website
        return 0

    except requests.RequestException as e:
        return -1  # Error occurred during URL fetch



#11. Right click
def rightClick(url):
    try:
        # Fetch the HTML content of the website
        response = requests.get(url)
        html_content = response.text

        # Parse the HTML using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract the value of the right-click attribute (if available)
        right_click_attribute = None


         # Replace 'data-right-click' with the actual attribute you are looking for
        element = soup.find(attrs={"data-right-click": True})
        if element:
            right_click_attribute = element["data-right-click"]

        # Check if the right-click attribute is present
        if right_click_attribute:
            return 1  # Phishing website detected due to right-click attribute

        return 0  # Safe website - no right-click attribute found

    except requests.RequestException as e:
        return -1  # Error occurred during URL fetch



#12 Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1


#13 Special characters
def count_special_characters(url):
    # Define a regular expression pattern to match special characters
    special_characters = r"[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]"

    # Use regex to find and count the special characters in the URL
    count = len(re.findall(special_characters, url))

    return count

#14 content length
def get_content_length(url):
    try:
        response = requests.head(url)
        content_length = response.headers.get("content-length")
        if content_length is not None:
            return int(content_length)
        else:
            return -1  # Return -1 for URLs with no content length in the headers
    except requests.exceptions.RequestException:
        return -1  # Return -1 for failed requests


#15 no of subdomains in url
def extract_subdomain_count(url):
    try:
        parsed_url = urlparse(url)
        # Split the hostname by periods and count the parts (subdomains)
        subdomain_count = len(parsed_url.netloc.split('.'))
        return subdomain_count
    except ValueError:
        return 0  # Return 0 for URLs with no valid subdomains

#16 listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

#17 Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0

# 19 Favicon detection involves fetching and analyzing the website's HTML to check if it includes a reference to a favicon
def extract_favicon_presence(url):
    try:
        # Fetch the HTML content of the website
        response = requests.get(url)
        html_content = response.text

        # Parse the HTML using BeautifulSoup
        soup = BeautifulSoup(html_content, 'html.parser')

        # Search for the presence of a favicon link tag
        favicon_link = soup.find("link", rel="icon")

        if favicon_link:
            return 1  # Favicon link found
        else:
            return 0  # Favicon link not found
    except requests.exceptions.RequestException:
        return 0  # Favicon link not found (assuming error means absence of favicon)


#20. Domain Registration Length:
#Phishing domains may have shorter registration periods.
def domain_registration_length(url):
    try:
        # Extract the domain from the URL
        domain = url.split('//')[1].split('/')[0]

        # Query WHOIS information for the domain
        domain_info = whois.whois(domain)

        # Get the creation date of the domain
        creation_date = domain_info.creation_date

        # Calculate the registration length in days
        registration_length = (datetime.now() - creation_date).days

        return registration_length

    except Exception as e:
        return 0

def check_phishing(url):
        # Get the registration length
        registration_length = domain_registration_length(url)

        # Define a threshold for registration length (adjust as needed)
        threshold = 365  # One year

        # Check if the registration length is below the threshold
        if registration_length > threshold:
            return 1  # Phishing website
        else:
            return 0  # Safe website


#21. check the Top-Level Domain :
#Some TLDs are more commonly associated with phishing. Compare the TLD to a list of common legitimate TLDs
def check_tld(url):
    try:
        # Extract the TLD from the URL
        parsed_url = urlparse(url)
        tld = parsed_url.netloc.split('.')[-1].lower()

        # List of common legitimate TLDs
        legitimate_tlds = ['com', 'net', 'org', 'edu', 'gov', 'in']

        # Check if the TLD is in the list of common legitimate TLDs
        if tld in legitimate_tlds:
            return 0  # Safe website
        else:
            return 1  # Phishing website

    except Exception as e:
        return -1  # Error occurred during processing



#22. Lexical Analysis : Analyzing the lexical structure of the URL for patterns commonly associated with phishing.
def lexical_analysis(url):
    try:
        # Extract the domain from the URL
        domain = re.search('https?://([^/]+)', url).group(1)

        # Check for patterns commonly associated with phishing
        patterns_phishing = [
            'login', 'signin', 'account', 'secure', 'update', 'verification',
            'confirm', 'password', 'admin', 'support', 'banking', 'paypal', 'login.php',
            'reset', 'verify', 'customer', 'service', 'alert', 'notice'
        ]

        for pattern in patterns_phishing:
            if re.search(pattern, domain, re.IGNORECASE):
                return 1  # Phishing website detected

        return 0  # Safe website

    except Exception as e:

        return -1  # Error occurred during processing



#23. Presence of hyphens in a domain can be considered as phishing
def check_hyphens(url):
    try:
        # Extract the domain from the URL
        domain = re.search('https?://([^/]+)', url).group(1)

        # Check if the domain contains hyphens
        if '-' in domain:
            return 1  # Phishing website detected due to hyphens in the domain
        else:
            return 0  # Safe website

    except Exception as e:
        return -1  # Error occurred during processing


#24. Presence of @ Symbol
def check_at_symbol(url):
    try:
        # Extract the path part of the URL
        path = url.split('//')[1].split('/')[1]

        # Check if "@" symbol is present in the path
        if '@' in path:
            return 1  # Phishing website
        else:
            return 0  # Safe website

    except Exception as e:

        return 1  # Error occurred during processing


# 25 Status code
import requests

def get_status_code(url):
    try:
        response = requests.get(url)
        return response.status_code
    except requests.exceptions.RequestException:
        return -1  # An error occurred while fetching the URL


# Vectorizing all the extracted features in list
def extract_features_from_url(url):

  features = []


 #features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(prefixSuffix(url))

  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(url))
  features.append(rightClick(url))
  features.append(forwarding(response))


  features.append(count_special_characters(url))
  features.append(get_content_length(url))
  features.append(extract_subdomain_count(url))
  features.append(tinyURL(url))

  features.append(extract_favicon_presence(url))
  features.append(check_phishing(url))  
  features.append(check_tld(url))
  features.append(lexical_analysis(url))
  features.append(check_hyphens(url))


  features.append(get_status_code(url))

  return features

xgb = XGBClassifier(n_estimators=100)
training_start = time.perf_counter()
xgb.fit(X_train, y_train)

preds = xgb.predict(X_test)
acc_xgb = (preds == y_test).sum().astype(float) / len(preds)*100


print("XGBoost's prediction accuracy is: %3.2f" % (acc_xgb))

# from sklearn.metrics import confusion_matrix, accuracy_score
# import seaborn as sns
# import matplotlib.pyplot as plt

# cm = confusion_matrix(y_test,preds)

#Plot the confusion matrix.
# sns.heatmap(cm,
#             annot=True,
#             fmt='g')
# plt.ylabel('Prediction',fontsize=13)
# plt.xlabel('Actual',fontsize=13)
# plt.title('Confusion Matrix',fontsize=17)
# plt.show()

from sklearn.metrics import accuracy_score
accuracy = accuracy_score(y_test, preds)
print("Accuracy   :", accuracy)

import pickle

with open('model_with_feature_extraction.pkl', 'wb') as model_file:
    model_data = {'model': xgb, 'feature_extraction_function': extract_features_from_url}
    pickle.dump(model_data, model_file)

import pickle

with open('model_with_feature_extraction.pkl', 'rb') as model_file:
    model_data = pickle.load(model_file)

loaded_model = model_data['model']
loaded_feature_extraction_function = model_data['feature_extraction_function']

# Define a function to make predictions using the loaded model and feature extraction function
def make_prediction(url):
    input_x = loaded_feature_extraction_function(url)
    print(input_x)
    prediction = loaded_model.predict([input_x])
    return prediction[0]

# url = 'http://shadetreetechnology.com/V4/validation/a111aedc8ae390eabcfa130e041a10a4 '
# url = 'https://facebook.com'

# result = make_prediction(url)
# print("Prediction:", result)