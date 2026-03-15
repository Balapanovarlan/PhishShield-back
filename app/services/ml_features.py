from bs4 import BeautifulSoup
from urllib.parse import urlparse

class MLFeatureExtractor:
    """Extracts features from HTML soup for ML model prediction."""
    
    @staticmethod
    def extract_features(soup: BeautifulSoup) -> list:
        """Returns a vector of 43 features based on the HTML content."""
        return [
            MLFeatureExtractor.has_title(soup),
            MLFeatureExtractor.has_input(soup),
            MLFeatureExtractor.has_button(soup),
            MLFeatureExtractor.has_image(soup),
            MLFeatureExtractor.has_submit(soup),
            MLFeatureExtractor.has_link(soup),
            MLFeatureExtractor.has_password(soup),
            MLFeatureExtractor.has_email_input(soup),
            MLFeatureExtractor.has_hidden_element(soup),
            MLFeatureExtractor.has_audio(soup),
            MLFeatureExtractor.has_video(soup),
            MLFeatureExtractor.number_of_inputs(soup),
            MLFeatureExtractor.number_of_buttons(soup),
            MLFeatureExtractor.number_of_images(soup),
            MLFeatureExtractor.number_of_option(soup),
            MLFeatureExtractor.number_of_list(soup),
            MLFeatureExtractor.number_of_th(soup),
            MLFeatureExtractor.number_of_tr(soup),
            MLFeatureExtractor.number_of_href(soup),
            MLFeatureExtractor.number_of_paragraph(soup),
            MLFeatureExtractor.number_of_script(soup),
            MLFeatureExtractor.length_of_title(soup),
            MLFeatureExtractor.has_h1(soup),
            MLFeatureExtractor.has_h2(soup),
            MLFeatureExtractor.has_h3(soup),
            MLFeatureExtractor.length_of_text(soup),
            MLFeatureExtractor.number_of_clickable_button(soup),
            MLFeatureExtractor.number_of_a(soup),
            MLFeatureExtractor.number_of_img(soup),
            MLFeatureExtractor.number_of_div(soup),
            MLFeatureExtractor.number_of_figure(soup),
            MLFeatureExtractor.has_footer(soup),
            MLFeatureExtractor.has_form(soup),
            MLFeatureExtractor.has_text_area(soup),
            MLFeatureExtractor.has_iframe(soup),
            MLFeatureExtractor.has_text_input(soup),
            MLFeatureExtractor.number_of_meta(soup),
            MLFeatureExtractor.has_nav(soup),
            MLFeatureExtractor.has_object(soup),
            MLFeatureExtractor.has_picture(soup),
            MLFeatureExtractor.number_of_sources(soup),
            MLFeatureExtractor.number_of_span(soup),
            MLFeatureExtractor.number_of_table(soup)
        ]

    # --- Feature Extraction Helper Methods ---
    @staticmethod
    def has_title(soup): return 1 if soup.title and len(soup.title.text) > 0 else 0
    @staticmethod
    def has_input(soup): return 1 if soup.find_all("input") else 0
    @staticmethod
    def has_button(soup): return 1 if soup.find_all("button") else 0
    @staticmethod
    def has_image(soup): return 1 if soup.find_all("img") or soup.find_all("image") else 0
    @staticmethod
    def has_submit(soup):
        for b in soup.find_all("input"):
            if b.get("type") == "submit": return 1
        return 0
    @staticmethod
    def has_link(soup): return 1 if soup.find_all("link") else 0
    @staticmethod
    def has_password(soup):
        for i in soup.find_all("input"):
            if (i.get("type") or i.get("name") or i.get("id")) == "password": return 1
        return 0
    @staticmethod
    def has_email_input(soup):
        for i in soup.find_all("input"):
            if (i.get("type") or i.get("id") or i.get("name")) == "email": return 1
        return 0
    @staticmethod
    def has_hidden_element(soup):
        for i in soup.find_all("input"):
            if i.get("type") == "hidden": return 1
        return 0
    @staticmethod
    def has_audio(soup): return 1 if soup.find_all("audio") else 0
    @staticmethod
    def has_video(soup): return 1 if soup.find_all("video") else 0
    @staticmethod
    def number_of_inputs(soup): return len(soup.find_all("input"))
    @staticmethod
    def number_of_buttons(soup): return len(soup.find_all("button"))
    @staticmethod
    def number_of_images(soup): 
        count = len(soup.find_all("img")) + len(soup.find_all("image"))
        for m in soup.find_all("meta"):
            if m.get("type") == "image" or m.get("name") == "image": count += 1
        return count
    @staticmethod
    def number_of_option(soup): return len(soup.find_all("option"))
    @staticmethod
    def number_of_list(soup): return len(soup.find_all("li"))
    @staticmethod
    def number_of_th(soup): return len(soup.find_all("th"))
    @staticmethod
    def number_of_tr(soup): return len(soup.find_all("tr"))
    @staticmethod
    def number_of_href(soup): return sum(1 for l in soup.find_all("link") if l.get("href"))
    @staticmethod
    def number_of_paragraph(soup): return len(soup.find_all("p"))
    @staticmethod
    def number_of_script(soup): return len(soup.find_all("script"))
    @staticmethod
    def length_of_title(soup): return len(soup.title.text) if soup.title else 0
    @staticmethod
    def has_h1(soup): return 1 if soup.find_all("h1") else 0
    @staticmethod
    def has_h2(soup): return 1 if soup.find_all("h2") else 0
    @staticmethod
    def has_h3(soup): return 1 if soup.find_all("h3") else 0
    @staticmethod
    def length_of_text(soup): return len(soup.get_text())
    @staticmethod
    def number_of_clickable_button(soup):
        return sum(1 for b in soup.find_all("button") if b.get("type") == "button")
    @staticmethod
    def number_of_a(soup): return len(soup.find_all("a"))
    @staticmethod
    def number_of_img(soup): return len(soup.find_all("img"))
    @staticmethod
    def number_of_div(soup): return len(soup.find_all("div"))
    @staticmethod
    def number_of_figure(soup): return len(soup.find_all("figure"))
    @staticmethod
    def has_footer(soup): return 1 if soup.find_all("footer") else 0
    @staticmethod
    def has_form(soup): return 1 if soup.find_all("form") else 0
    @staticmethod
    def has_text_area(soup): return 1 if soup.find_all("textarea") else 0
    @staticmethod
    def has_iframe(soup): return 1 if soup.find_all("iframe") else 0
    @staticmethod
    def has_text_input(soup):
        for i in soup.find_all("input"):
            if i.get("type") == "text": return 1
        return 0
    @staticmethod
    def number_of_meta(soup): return len(soup.find_all("meta"))
    @staticmethod
    def has_nav(soup): return 1 if soup.find_all("nav") else 0
    @staticmethod
    def has_object(soup): return 1 if soup.find_all("object") else 0
    @staticmethod
    def has_picture(soup): return 1 if soup.find_all("picture") else 0
    @staticmethod
    def number_of_sources(soup): return len(soup.find_all("source"))
    @staticmethod
    def number_of_span(soup): return len(soup.find_all("span"))
    @staticmethod
    def number_of_table(soup): return len(soup.find_all("table"))
