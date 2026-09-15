
# ============================================================
# CYBERSHIELD - LEVEL 3 HYBRID PHISHING URL DETECTOR
# ============================================================
#
# Uses:
#   1. Character-level TF-IDF + Logistic Regression
#   2. Random Forest URL structural features
#   3. Generic security heuristics
#   4. Generic typosquatting / look-alike detection
#
# IMPORTANT:
# No phishing URL is hard-coded.
#
# The detector learns legitimate-domain references from the
# dataset and also uses a small set of known legitimate
# domains as reference points. It never stores:
#
#     rnicrosoft.com
#     g00gle.com
#     paypa1.com
#
# as phishing rules.
# ============================================================

import re
import joblib
import pandas as pd

from pathlib import Path
from urllib.parse import urlparse
from difflib import SequenceMatcher


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "Models"
DATA_DIR = BASE_DIR / "Data"

RF_MODEL_PATH = MODELS_DIR / "domain_split_model.pkl"
RF_FEATURE_PATH = MODELS_DIR / "domain_split_features.pkl"

TFIDF_MODEL_PATH = MODELS_DIR / "url_tfidf_model.pkl"
TFIDF_VECTORIZER_PATH = MODELS_DIR / "url_tfidf_vectorizer.pkl"

DATASET_PATH = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"


# ============================================================
# LEGITIMATE REFERENCE DOMAINS
# ============================================================
# These are NOT phishing rules. They are legitimate references
# used to detect a new domain that differs by a small number of
# characters.
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "google.co.in",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazon.in",
    "wikipedia.org",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "netflix.com",
    "github.com",
    "youtube.com",
    "gmail.com",
    "yahoo.com",
    "adobe.com",
    "dropbox.com",
    "zoom.us",
    "spotify.com",
}


# ============================================================
# GENERIC SECURITY INDICATORS
# ============================================================

SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "confirm",
    "bank",
    "payment",
    "wallet",
    "bonus",
    "free",
    "alert",
    "suspend",
    "unlock",
    "authenticate",
    "authentication",
    "credential",
    "recover",
    "recovery",
    "validate",
    "validation",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "work",
    "zip",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
}


# ============================================================
# MODEL LOADING
# ============================================================

try:
    rf_model = joblib.load(RF_MODEL_PATH)
    rf_feature_names = joblib.load(RF_FEATURE_PATH)
except Exception as exc:
    raise RuntimeError(
        "Could not load Random Forest files.\n"
        f"Model: {RF_MODEL_PATH}\n"
        f"Features: {RF_FEATURE_PATH}\n"
        f"Error: {exc}"
    ) from exc


try:
    tfidf_model = joblib.load(TFIDF_MODEL_PATH)
    tfidf_vectorizer = joblib.load(TFIDF_VECTORIZER_PATH)
except Exception as exc:
    raise RuntimeError(
        "Could not load TF-IDF files.\n"
        f"Model: {TFIDF_MODEL_PATH}\n"
        f"Vectorizer: {TFIDF_VECTORIZER_PATH}\n"
        f"Error: {exc}"
    ) from exc


# ============================================================
# NORMALIZATION HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    url = str(url).strip()

    if not url:
        return ""

    if not url.lower().startswith(("http://", "https://")):
        return "https://" + url

    return url


def normalize_domain(domain: str) -> str:
    domain = str(domain).strip().lower()

    if not domain:
        return ""

    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    domain = domain.rstrip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def get_hostname(url: str) -> str:
    normalized = normalize_url(url)

    if not normalized:
        return ""

    try:
        return (
            urlparse(normalized).hostname
            or ""
        ).lower()
    except Exception:
        return ""


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_registrable_domain(hostname: str) -> str:
    """
    Return the effective domain used for comparison.

    Examples:
        docs.google.com -> google.com
        login.microsoft.com -> microsoft.com
        rnicrosoft.com -> rnicrosoft.com
    """

    hostname = normalize_domain(hostname)

    if not hostname:
        return ""

    parts = hostname.split(".")

    if len(parts) < 2:
        return hostname

    common_two_part_suffixes = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
    }

    suffix = ".".join(parts[-2:])

    if (
        suffix in common_two_part_suffixes
        and len(parts) >= 3
    ):
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def get_domain_label(domain: str) -> str:
    registrable = get_registrable_domain(domain)

    if not registrable:
        return ""

    return registrable.split(".")[0]


def get_tld(domain: str) -> str:
    domain = normalize_domain(domain)

    if "." not in domain:
        return ""

    return domain.split(".")[-1]


# ============================================================
# DATASET LEGITIMATE DOMAIN REFERENCES
# ============================================================

def load_dataset_legitimate_domains() -> set[str]:
    if not DATASET_PATH.exists():
        return set()

    try:
        df = pd.read_csv(
            DATASET_PATH,
            low_memory=False,
        )
    except Exception:
        return set()

    url_column = None
    label_column = None

    for column in df.columns:
        name = str(column).strip().lower()

        if name in {"url", "domain"}:
            url_column = column

        if name == "label":
            label_column = column

    if url_column is None or label_column is None:
        return set()

    domains = set()

    for _, row in df.iterrows():

        try:
            label = int(row[label_column])
        except Exception:
            continue

        # Your dataset convention:
        # 0 = legitimate
        if label != 0:
            continue

        value = row[url_column]

        if pd.isna(value):
            continue

        value = str(value).strip()

        if value.lower().startswith(
            ("http://", "https://")
        ):
            domain = get_hostname(value)
        else:
            domain = normalize_domain(value)

        domain = normalize_domain(domain)

        if domain:
            domains.add(domain)

    return domains


DATASET_LEGITIMATE_DOMAINS = (
    load_dataset_legitimate_domains()
)


# ============================================================
# COMBINED LEGITIMATE REFERENCE SET
# ============================================================

LEGITIMATE_REFERENCE_DOMAINS = (
    DATASET_LEGITIMATE_DOMAINS
    |
    {
        normalize_domain(domain)
        for domain in TRUSTED_DOMAINS
    }
)


# ============================================================
# VISUAL CHARACTER NORMALIZATION
# ============================================================

def visual_normalize(value: str) -> str:
    """
    Generic normalization for common digit/letter substitutions.

    This does not contain any brand name.
    """

    table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
    })

    return str(value).translate(table)


# ============================================================
# EDIT DISTANCE
# ============================================================

def levenshtein_distance(
    first: str,
    second: str,
) -> int:

    first = str(first)
    second = str(second)

    if first == second:
        return 0

    if len(first) < len(second):
        first, second = second, first

    previous = list(
        range(len(second) + 1)
    )

    for i, char_first in enumerate(
        first,
        start=1,
    ):

        current = [i]

        for j, char_second in enumerate(
            second,
            start=1,
        ):

            insertion = (
                current[j - 1] + 1
            )

            deletion = (
                previous[j] + 1
            )

            substitution = (
                previous[j - 1]
                +
                (
                    char_first
                    != char_second
                )
            )

            current.append(
                min(
                    insertion,
                    deletion,
                    substitution,
                )
            )

        previous = current

    return previous[-1]


# ============================================================
# DOMAIN SIMILARITY
# ============================================================

def find_similar_legitimate_domain(
    hostname: str,
):
    """
    Detect a new domain that differs only slightly from a
    legitimate domain.

    Critical rules:

    1. Exact legitimate domains are safe.
    2. We compare the actual domain label, not subdomains.
    3. The TLD does NOT need to be identical.
    4. If spelling is identical but TLD differs, it is NOT a typo.
    5. One or two character changes can be suspicious.
    """

    hostname = normalize_domain(hostname)

    if not hostname:
        return None

    candidate_registrable = (
        get_registrable_domain(hostname)
    )

    candidate_label = get_domain_label(
        candidate_registrable
    )

    if not candidate_label:
        return None

    # Exact legitimate domain.
    if candidate_registrable in (
        LEGITIMATE_REFERENCE_DOMAINS
    ):
        return None

    if len(candidate_label) < 5:
        return None

    best = None

    for reference in (
        LEGITIMATE_REFERENCE_DOMAINS
    ):

        reference_registrable = (
            get_registrable_domain(reference)
        )

        reference_label = (
            get_domain_label(
                reference_registrable
            )
        )

        if not reference_label:
            continue

        # Same spelling but different TLD:
        # microsoft.com vs microsoft.net
        # -> NOT typosquatting.
        if candidate_label == reference_label:
            continue

        if len(reference_label) < 5:
            continue

        # Avoid unrelated domain comparisons.
        if abs(
            len(candidate_label)
            -
            len(reference_label)
        ) > 2:
            continue

        distance = levenshtein_distance(
            candidate_label,
            reference_label,
        )

        similarity = SequenceMatcher(
            None,
            candidate_label,
            reference_label,
        ).ratio()

        visual_similarity = SequenceMatcher(
            None,
            visual_normalize(candidate_label),
            visual_normalize(reference_label),
        ).ratio()

        # ----------------------------------------------------
        # Strong generic typo conditions
        # ----------------------------------------------------

        is_one_edit = (
            distance == 1
            and similarity >= 0.80
        )

        is_two_edit = (
            distance == 2
            and similarity >= 0.80
        )

        is_visual_substitution = (
            visual_similarity >= 0.98
            and similarity >= 0.70
        )

        if not (
            is_one_edit
            or is_two_edit
            or is_visual_substitution
        ):
            continue

        candidate = {
            "similar_domain": reference_registrable,
            "distance": distance,
            "similarity": similarity,
            "visual_similarity": visual_similarity,
        }

        if best is None:
            best = candidate
            continue

        # Prefer lower edit distance.
        if distance < best["distance"]:
            best = candidate
            continue

        # If edit distance is equal, prefer higher similarity.
        if (
            distance == best["distance"]
            and similarity > best["similarity"]
        ):
            best = candidate

    return best


# ============================================================
# TYPOSQUATTING DETECTOR
# ============================================================

def detect_typosquatting(hostname: str):
    result = find_similar_legitimate_domain(
        hostname
    )

    if result is None:
        return None

    return {
        "detected": True,
        "similar_domain": result[
            "similar_domain"
        ],
        "distance": result[
            "distance"
        ],
        "similarity": result[
            "similarity"
        ],
        "visual_similarity": result[
            "visual_similarity"
        ],
    }


# ============================================================
# TRUSTED DOMAIN
# ============================================================

def is_trusted_domain(hostname: str) -> bool:
    hostname = normalize_domain(
        hostname
    )

    registrable = get_registrable_domain(
        hostname
    )

    return (
        registrable
        in
        LEGITIMATE_REFERENCE_DOMAINS
    )


# ============================================================
# URL FEATURE EXTRACTION
# ============================================================

def extract_url_features(url: str) -> dict:

    url = str(url).strip()

    test_url = url

    if not test_url.lower().startswith(
        ("http://", "https://")
    ):
        test_url = "http://" + test_url

    parsed = urlparse(test_url)

    hostname = (
        parsed.hostname
        or ""
    ).lower()

    path = (
        parsed.path
        or ""
    ).lower()

    query = (
        parsed.query
        or ""
    ).lower()

    url_lower = url.lower()

    # --------------------------------------------------------
    # Length
    # --------------------------------------------------------

    url_length = len(url)

    domain_length = len(hostname)

    path_length = len(path)

    query_length = len(query)

    # --------------------------------------------------------
    # Characters
    # --------------------------------------------------------

    letters = sum(
        c.isalpha()
        for c in url
    )

    digits = sum(
        c.isdigit()
        for c in url
    )

    dots = url.count(".")

    hyphens = url.count("-")

    slashes = url.count("/")

    question_marks = url.count("?")

    equals = url.count("=")

    ampersands = url.count("&")

    at_symbols = url.count("@")

    percent = url.count("%")

    underscores = url.count("_")

    special_characters = sum(
        not c.isalnum()
        for c in url
    )

    # --------------------------------------------------------
    # Ratios
    # --------------------------------------------------------

    if url_length > 0:

        digit_ratio = (
            digits / url_length
        )

        letter_ratio = (
            letters / url_length
        )

        special_ratio = (
            special_characters
            /
            url_length
        )

    else:

        digit_ratio = 0.0

        letter_ratio = 0.0

        special_ratio = 0.0

    # --------------------------------------------------------
    # Subdomains
    # --------------------------------------------------------

    parts = [
        p
        for p in hostname.split(".")
        if p
    ]

    subdomains = max(
        len(parts) - 2,
        0
    )

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}"
        r"\d{1,3}$"
    )

    is_domain_ip = int(
        bool(
            re.match(
                ip_pattern,
                hostname
            )
        )
    )

    # --------------------------------------------------------
    # Scheme
    # --------------------------------------------------------

    is_https = int(
        parsed.scheme.lower()
        ==
        "https"
    )

    # --------------------------------------------------------
    # URL structures
    # --------------------------------------------------------

    has_at_symbol = int(
        "@" in url
    )

    has_double_slash = int(
        "//" in url_lower[8:]
    )

    has_https_in_path = int(
        "https" in path
    )

    has_www = int(
        hostname.startswith("www.")
    )

    # --------------------------------------------------------
    # Security keyword count
    # --------------------------------------------------------

    suspicious_word_count = sum(
        word in url_lower
        for word in SUSPICIOUS_WORDS
    )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    uses_shortener = int(
        any(
            hostname == service
            or hostname.endswith(
                "." + service
            )
            for service in URL_SHORTENERS
        )
    )

    # --------------------------------------------------------
    # Generic security words in path
    # --------------------------------------------------------

    brand_in_path = int(
        any(
            word in path
            for word in {
                "login",
                "signin",
                "verify",
                "verification",
                "account",
                "password",
                "security",
            }
        )
    )

    # --------------------------------------------------------
    # TLD
    # --------------------------------------------------------

    tld = get_tld(hostname)

    suspicious_tld = int(
        tld in SUSPICIOUS_TLDS
    )

    # --------------------------------------------------------
    # Length indicators
    # --------------------------------------------------------

    very_long_domain = int(
        domain_length > 30
    )

    very_long_url = int(
        url_length > 100
    )

    many_subdomains = int(
        subdomains >= 3
    )

    return {
        "URLLength": url_length,
        "DomainLength": domain_length,
        "PathLength": path_length,
        "QueryLength": query_length,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfDots": dots,
        "NoOfHyphens": hyphens,
        "NoOfSlashes": slashes,
        "NoOfQMarkInURL": question_marks,
        "NoOfEqualsInURL": equals,
        "NoOfAmpersandInURL": ampersands,
        "NoOfAtSymbol": at_symbols,
        "NoOfPercent": percent,
        "NoOfUnderscore": underscores,
        "DigitRatio": digit_ratio,
        "LetterRatio": letter_ratio,
        "SpecialCharRatio": special_ratio,
        "IsDomainIP": is_domain_ip,
        "IsHTTPS": is_https,
        "NoOfSubDomain": subdomains,
        "SuspiciousWordCount": suspicious_word_count,
        "UsesURLShortener": uses_shortener,
        "HasAtSymbol": has_at_symbol,
        "HasDoubleSlash": has_double_slash,
        "HasHTTPSInPath": has_https_in_path,
        "HasWWW": has_www,
        "BrandInPath": brand_in_path,
        "SuspiciousTLD": suspicious_tld,
        "VeryLongDomain": very_long_domain,
        "VeryLongURL": very_long_url,
        "ManySubdomains": many_subdomains,
    }


# ============================================================
# GENERIC SECURITY RULES
# ============================================================

def security_rules(url: str) -> dict:

    url = str(url).strip()

    hostname = get_hostname(
        url
    )

    url_lower = url.lower()

    score = 0

    reasons = []

    # --------------------------------------------------------
    # IP address
    # --------------------------------------------------------

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}"
        r"\d{1,3}$"
    )

    is_ip = bool(
        re.match(
            ip_pattern,
            hostname
        )
    )

    if is_ip:

        score += 4

        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )

    # --------------------------------------------------------
    # @ symbol
    # --------------------------------------------------------

    if "@" in url_lower:

        score += 5

        reasons.append(
            "The URL contains an '@' symbol."
        )

    # --------------------------------------------------------
    # Suspicious slash
    # --------------------------------------------------------

    normalized = normalize_url(url)

    if "//" in normalized[8:]:

        score += 3

        reasons.append(
            "The URL contains a suspicious double-slash pattern."
        )

    # --------------------------------------------------------
    # Security keywords
    # --------------------------------------------------------

    found_words = [
        word
        for word in SUSPICIOUS_WORDS
        if word in url_lower
    ]

    if len(found_words) >= 3:

        score += 4

        reasons.append(
            "The URL contains several phishing-related keywords."
        )

    elif len(found_words) == 2:

        score += 3

        reasons.append(
            "The URL contains multiple phishing-related keywords."
        )

    elif len(found_words) == 1:

        score += 1

        reasons.append(
            "The URL contains a phishing-related keyword."
        )

    # --------------------------------------------------------
    # Login + password/verify/account combination
    # --------------------------------------------------------

    authentication_words = {
        "login",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "credential",
        "authenticate",
        "authentication",
    }

    account_words = {
        "account",
        "update",
        "confirm",
    }

    has_authentication = bool(
        authentication_words
        &
        set(found_words)
    )

    has_account_action = bool(
        account_words
        &
        set(found_words)
    )

    if (
        has_authentication
        and
        has_account_action
    ):

        score += 2

        reasons.append(
            "The URL combines authentication and account-related actions."
        )

    # --------------------------------------------------------
    # Suspicious TLD
    # --------------------------------------------------------

    tld = get_tld(
        hostname
    )

    if tld in SUSPICIOUS_TLDS:

        score += 2

        reasons.append(
            f"The URL uses the potentially suspicious .{tld} extension."
        )

    # --------------------------------------------------------
    # URL shortener
    # --------------------------------------------------------

    if hostname in URL_SHORTENERS:

        score += 2

        reasons.append(
            "The URL uses a URL-shortening service."
        )

    # --------------------------------------------------------
    # Multiple subdomains
    # --------------------------------------------------------

    subdomain_count = max(
        len(
            [
                p
                for p in hostname.split(".")
                if p
            ]
        )
        - 2,
        0,
    )

    if subdomain_count >= 3:

        score += 2

        reasons.append(
            "The URL contains multiple subdomains."
        )

    # --------------------------------------------------------
    # Very long URL
    # --------------------------------------------------------

    if len(url) > 150:

        score += 2

        reasons.append(
            "The URL is unusually long."
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if url_lower.startswith(
        "http://"
    ):

        score += 1

        reasons.append(
            "The URL uses HTTP instead of HTTPS."
        )

    return {
        "score": score,
        "reasons": reasons,
        "hostname": hostname,
        "found_words": found_words,
        "is_ip": is_ip,
    }


# ============================================================
# RANDOM FOREST PREDICTION
# ============================================================

def random_forest_prediction(
    url: str
):
    features = extract_url_features(
        url
    )

    sample = pd.DataFrame(
        [features]
    )

    sample = sample.reindex(
        columns=rf_feature_names,
        fill_value=0,
    )

    probabilities = (
        rf_model.predict_proba(
            sample
        )[0]
    )

    class_probabilities = dict(
        zip(
            rf_model.classes_,
            probabilities
        )
    )

    legitimate = float(
        class_probabilities.get(
            0,
            0.0
        )
    )

    phishing = float(
        class_probabilities.get(
            1,
            0.0
        )
    )

    return legitimate, phishing


# ============================================================
# TF-IDF PREDICTION
# ============================================================

def tfidf_prediction(
    url: str
):
    vector = (
        tfidf_vectorizer.transform(
            [str(url).strip()]
        )
    )

    probabilities = (
        tfidf_model.predict_proba(
            vector
        )[0]
    )

    class_probabilities = dict(
        zip(
            tfidf_model.classes_,
            probabilities
        )
    )

    legitimate = float(
        class_probabilities.get(
            0,
            0.0
        )
    )

    phishing = float(
        class_probabilities.get(
            1,
            0.0
        )
    )

    return legitimate, phishing


# ============================================================
# MAIN PREDICTOR
# ============================================================

def predict_url(
    url: str
) -> dict:

    url = str(url).strip()

    if not url:

        return {
            "prediction": 0,
            "label": "INVALID",
            "risk_score": 0,
            "legitimate_probability": 0.0,
            "phishing_probability": 0.0,
            "reasons": [
                "Please enter a URL."
            ],
        }

    hostname = get_hostname(
        url
    )

    if not hostname:

        return {
            "prediction": 1,
            "label": "PHISHING",
            "risk_score": 9,
            "legitimate_probability": 0.05,
            "phishing_probability": 0.95,
            "reasons": [
                "The URL does not contain a valid hostname."
            ],
        }

    # ========================================================
    # SECURITY RULES
    # ========================================================

    rules = security_rules(
        url
    )

    heuristic_score = rules[
        "score"
    ]

    heuristic_reasons = rules[
        "reasons"
    ]

    heuristic_probability = min(
        heuristic_score / 10.0,
        1.0,
    )

    # ========================================================
    # EXACT LEGITIMATE DOMAIN
    # ========================================================

    registrable = get_registrable_domain(
        hostname
    )

    exact_legitimate = (
        registrable
        in
        LEGITIMATE_REFERENCE_DOMAINS
    )

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    typo_result = detect_typosquatting(
        hostname
    )

    typo_probability = 0.0

    similar_domain = None

    similarity = 0.0

    if typo_result:

        typo_probability = 1.0

        similar_domain = (
            typo_result[
                "similar_domain"
            ]
        )

        similarity = max(
            typo_result[
                "similarity"
            ],
            typo_result[
                "visual_similarity"
            ],
        )

        heuristic_score += 5

    # ========================================================
    # MACHINE LEARNING
    # ========================================================

    rf_legitimate, rf_phishing = (
        random_forest_prediction(
            url
        )
    )

    tfidf_legitimate, tfidf_phishing = (
        tfidf_prediction(
            url
        )
    )

    # ========================================================
    # HYBRID SCORE
    # ========================================================
    #
    # The two trained ML models provide the main prediction.
    # Generic security signals and typosquatting add evidence.
    #
    # ========================================================

    hybrid_phishing = (

        0.40 * tfidf_phishing

        +

        0.30 * rf_phishing

        +

        0.15 * min(
            heuristic_score / 10.0,
            1.0,
        )

        +

        0.15 * typo_probability
    )

    hybrid_phishing = min(
        max(
            hybrid_phishing,
            0.0
        ),
        1.0,
    )

    # ========================================================
    # DECISION LOGIC
    # ========================================================

    strong_typo = (
        typo_result is not None
    )

    strong_heuristic = (
        heuristic_score >= 7
    )

    # --------------------------------------------------------
    # Exact legitimate domain:
    # do not punish it just because the ML score is imperfect.
    # Strong URL-security evidence can still override it.
    # --------------------------------------------------------

    if exact_legitimate and not (
        strong_typo
        or
        strong_heuristic
    ):

        final_phishing = min(
            hybrid_phishing,
            0.10,
        )

        prediction = 0

        label = "LEGITIMATE"

    # --------------------------------------------------------
    # Strong typosquatting
    # --------------------------------------------------------

    elif strong_typo:

        final_phishing = max(
            hybrid_phishing,
            0.95,
        )

        prediction = 1

        label = "PHISHING"

    # --------------------------------------------------------
    # Strong generic security evidence
    # --------------------------------------------------------

    elif strong_heuristic:

        final_phishing = max(
            hybrid_phishing,
            0.90,
        )

        prediction = 1

        label = "PHISHING"

    # --------------------------------------------------------
    # Normal hybrid decision
    # --------------------------------------------------------

    else:

        final_phishing = hybrid_phishing

        if final_phishing >= 0.50:

            prediction = 1

            label = "PHISHING"

        else:

            prediction = 0

            label = "LEGITIMATE"

    # ========================================================
    # FINAL PROBABILITIES
    # ========================================================

    final_phishing = min(
        max(
            final_phishing,
            0.0
        ),
        1.0,
    )

    final_legitimate = (
        1.0
        -
        final_phishing
    )

    # ========================================================
    # RISK SCORE
    # ========================================================

    risk_score = round(
        final_phishing * 10
    )

    risk_score = min(
        max(
            risk_score,
            0
        ),
        10,
    )

    # ========================================================
    # EXPLANATION
    # ========================================================

    reasons = []

    if exact_legitimate:

        reasons.append(
            "The domain matches a legitimate domain reference."
        )

    if typo_result:

        reasons.append(
            "The domain is highly similar to "
            f"'{similar_domain}' "
            f"({similarity * 100:.1f}% similarity)."
        )

        reasons.append(
            "The domain appears to use a small "
            "character modification of a legitimate domain."
        )

    if tfidf_phishing >= 0.70:

        reasons.append(
            "The character-level TF-IDF model detected "
            "patterns associated with phishing."
        )

    if rf_phishing >= 0.70:

        reasons.append(
            "The Random Forest model detected suspicious "
            "URL structural characteristics."
        )

    for reason in heuristic_reasons:

        if reason not in reasons:

            reasons.append(
                reason
            )

    if not reasons:

        if prediction == 1:

            reasons.append(
                "The combined model detected phishing-like "
                "URL characteristics."
            )

        else:

            reasons.append(
                "The combined model found the URL more "
                "consistent with legitimate patterns."
            )

    # Remove duplicate reasons.
    clean_reasons = []

    for reason in reasons:

        if reason not in clean_reasons:

            clean_reasons.append(
                reason
            )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {

        "prediction":
            int(prediction),

        "label":
            label,

        "risk_score":
            int(risk_score),

        "legitimate_probability":
            float(final_legitimate),

        "phishing_probability":
            float(final_phishing),

        "reasons":
            clean_reasons[:5],

        # Extra fields for future UI use.
        "tfidf_phishing_probability":
            float(tfidf_phishing),

        "tfidf_legitimate_probability":
            float(tfidf_legitimate),

        "random_forest_phishing_probability":
            float(rf_phishing),

        "random_forest_legitimate_probability":
            float(rf_legitimate),

        "heuristic_probability":
            float(
                min(
                    heuristic_score / 10.0,
                    1.0,
                )
            ),

        "typosquatting_probability":
            float(typo_probability),

        "similar_legitimate_domain":
            similar_domain,

        "similarity":
            float(similarity),
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("CYBERSHIELD - LEVEL 3 HYBRID DETECTOR")
    print("=" * 70)

    print()
    print(
        f"Dataset legitimate domains: "
        f"{len(DATASET_LEGITIMATE_DOMAINS)}"
    )

    print(
        f"Legitimate references: "
        f"{len(LEGITIMATE_REFERENCE_DOMAINS)}"
    )

    print()

    test_urls = [

        # Legitimate
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "wikipedia.org",

        # Typosquatting
        "g00gle.com",
        "goog1e.com",
        "rnicrosoft.com",
        "micros0ft.com",
        "paypa1.com",
        "app1e.com",
        "amaz0n.com",

        # Security indicators
        "http://192.168.1.10/login/verify/account",
        "https://secure-login-example.xyz/account/verify",
        "http://example.com/login/password",
    ]

    for test_url in test_urls:

        print("-" * 70)

        print(
            f"URL: {test_url}"
        )

        try:

            result = predict_url(
                test_url
            )

            print(
                f"Prediction: {result['label']}"
            )

            print(
                f"Risk Score: "
                f"{result['risk_score']}/10"
            )

            print(
                f"Legitimate Probability: "
                f"{result['legitimate_probability'] * 100:.2f}%"
            )

            print(
                f"Phishing Probability: "
                f"{result['phishing_probability'] * 100:.2f}%"
            )

            print(
                f"Typosquatting Probability: "
                f"{result['typosquatting_probability'] * 100:.2f}%"
            )

            if result[
                "similar_legitimate_domain"
            ]:

                print(
                    "Similar Legitimate Domain: "
                    f"{result['similar_legitimate_domain']}"
                )

            print(
                "Reasons:"
            )

            for reason in result[
                "reasons"
            ]:

                print(
                    f"  - {reason}"
                )

        except Exception as exc:

            print(
                f"ERROR: {exc}"
            )

        print()

    print("=" * 70)
    print("TESTING FINISHED")
    print("=" * 70)
