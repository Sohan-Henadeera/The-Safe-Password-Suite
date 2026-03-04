"""
Password Security Suite
Developed by: Sohan Henadeera
Year: 2026

Usage & Attribution:
This code is open-source. If you use, adapt, or build upon this code for your 
own projects, please provide proper attribution by acknowledging the original 
author and linking back to the original GitHub repository.
"""
import streamlit as st
import requests
import hashlib
import re
import secrets
import string
import math

# PAGE SETUP
st.set_page_config(page_title="The Safe Password Suite", layout="centered", page_icon="🛡️")

# STYLE(CSS)
st.markdown("""
<style>
/* Import a modern, clean font similar to tile's San Francisco */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -tile-system, BlinkMacSystemFont, sans-serif;
}

/*NAVIGATION BAR (BUTTON STYLE)*/
/* Force center alignment for the Streamlit radio widget container */
[data-testid="stRadio"] {
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
}

/* Style the radiogroup to center its children */
[data-testid="stRadio"] > div[role="radiogroup"] {
    justify-content: center !important;
    margin: 0 auto;
    gap: 12px;
    margin-bottom: 2rem;
    display: flex;
    flex-wrap: wrap;
}

/* Force Inter font into all radio/nav elements */
[data-testid="stRadio"],
[data-testid="stRadio"] * {
    font-family: 'Inter', -tile-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif !important;
}

/* Hide the default radio button circles */
[data-testid="stRadio"] > div[role="radiogroup"] > label > div:first-child {
    display: none;
}

/* Style the labels to look like standard buttons (unselected state) */
[data-testid="stRadio"] > div[role="radiogroup"] > label {
    padding: 10px 24px;
    border-radius: 8px; 
    transition: all 0.16s ease;
    cursor: pointer;
    margin: 0;
    border: 1px solid #005fc9; 
    background-color: #0071e3; 
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.12);
    color: #ffffff;
    font-weight: 600 !important;
    letter-spacing: -0.01em !important;
}

/* Subtle hover effect for unselected items */
[data-testid="stRadio"] > div[role="radiogroup"] > label:hover {
    background-color: #005fc9; 
    border-color: #004bb0;
}

/* Selected state: Solid Blue Button look */
[data-testid="stRadio"] > div[role="radiogroup"] > label[data-checked="true"] {
    background-color: #0071e3 !important; 
    border-color: #003f99 !important;
    box-shadow: 0 8px 20px rgba(0, 55, 122, 0.36);
    color: #ffffff;
}

/* Unselected text styling */
[data-testid="stRadio"] > div[role="radiogroup"] > label > div {
    color: #ffffff !important; 
    font-weight: 600 !important;
    letter-spacing: -0.02em !important;
}

/* Keep the text white and bold when a button is selected */
[data-testid="stRadio"] > div[role="radiogroup"] > label[data-checked="true"] > div {
    color: white !important;
    font-weight: 600;
}

/*TYPOGRAPHY & LAYOUT*/
.tile-title {
    text-align: center;
    font-size: 3rem;
    font-weight: 700;
    letter-spacing: -0.03em;
    margin-bottom: 0.5rem;
}

.tile-subtitle {
    text-align: center;
    font-size: 1.25rem;
    font-weight: 400;
    color: #888888;
    margin-bottom: 2rem;
    line-height: 1.4;
}

.tile-body {
    text-align: center;
    font-size: 1.1rem;
    line-height: 1.6;
    max-width: 700px;
    margin: 0 auto 2rem auto;
    color: var(--text-color);
    opacity: 0.9;
}

.tile-card {
    background-color: rgba(150, 150, 150, 0.05);
    border-radius: 16px;
    padding: 30px;
    text-align: center;
    margin-bottom: 20px;
}

.tile-fact {
    background-color: rgba(0, 113, 227, 0.05);
    border-left: 4px solid #0071e3;
    padding: 16px 24px;
    border-radius: 0 12px 12px 0;
    margin: 0 auto 30px auto;
    max-width: 700px;
    font-size: 0.95rem;
    color: var(--text-color);
    text-align: left;
    line-height: 1.6;
}

/* Center text inside the main input fields */
.stTextInput > div > div > input {
    text-align: center;
    font-size: 1.1rem;
    border-radius: 12px;
}

/*FOOTER*/
.modern-footer {
    text-align: center;
    margin-top: 100px;
    padding-top: 30px;
    border-top: 1px solid rgba(150, 150, 150, 0.2);
    color: #888888;
    font-size: 0.9rem;
}

.modern-footer a {
    color: var(--text-color);
    text-decoration: none;
    margin: 0 15px;
    font-weight: 500;
    transition: opacity 0.2s;
}

.modern-footer a:hover {
    opacity: 0.6;
}
</style>
""", unsafe_allow_html=True)

#HELP FUNCTIONS
def check_pwned_api(password):
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars, tail = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5_chars}"
    
    try:
        response = requests.get(url)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == tail:
                    return int(count)
    except requests.RequestException:
        st.error("Error connecting to the Have I Been Pwned API. Please check your internet connection.")
    return 0 

def check_complexity(password):
    score = 0
    feedback = []
    if len(password) >= 12: score += 1
    else: feedback.append("Make it at least 12 characters.")
    if re.search(r"[A-Z]", password): score += 1
    else: feedback.append("Add an uppercase letter.")
    if re.search(r"[0-9]", password): score += 1
    else: feedback.append("Add a number.")
    if re.search(r"[!@#$%^&*]", password): score += 1
    else: feedback.append("Add a special character (!@#$% etc).")
    return score, feedback

def calculate_time_to_crack(password):
    """Estimates time to crack based on entropy and 100B guesses/sec."""
    if not password: return "Instant"
    pool_size = 0
    if re.search(r"[a-z]", password): pool_size += 26
    if re.search(r"[A-Z]", password): pool_size += 26
    if re.search(r"[0-9]", password): pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool_size += 32
    if pool_size == 0: pool_size = 26
    
    entropy = len(password) * math.log2(pool_size)
    guesses_per_second = 100 * 10**9 
    seconds = (2 ** entropy) / guesses_per_second
    
    if seconds < 1: return "Instant"
    elif seconds < 60: return f"{int(seconds)} Seconds"
    elif seconds < 3600: return f"{int(seconds/60)} Minutes"
    elif seconds < 86400: return f"{int(seconds/3600)} Hours"
    elif seconds < 31536000: return f"{int(seconds/86400)} Days"
    elif seconds < 3153600000: return f"{int(seconds/31536000)} Years"
    else: return f"{int(seconds/3153600000):,} Centuries"

def generate_secure_password(length, use_upper, use_nums, use_syms, keyword=""):
    characters = string.ascii_lowercase
    if use_upper: characters += string.ascii_uppercase
    if use_nums: characters += string.digits
    if use_syms: characters += "!@#$%^&*"
    
    if not characters:
        characters = string.ascii_lowercase
        
    if keyword:
        if len(keyword) >= length:
            remaining_length = 4 
        else:
            remaining_length = length - len(keyword)
            
        random_part = ''.join(secrets.choice(characters) for _ in range(remaining_length))
        insert_pos = secrets.randbelow(remaining_length + 1)
        return random_part[:insert_pos] + keyword + random_part[insert_pos:]
        
    return ''.join(secrets.choice(characters) for _ in range(length))

def simulate_hashing(password):
    salt = secrets.token_hex(8) 
    salted_password = salt + password
    hashed = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed

def caesar_cipher(text, shift):
    """Applies a basic Caesar Cipher shift to letters in the text."""
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

# NAVIGATION
page = st.radio(
    "Navigation", 
    ["Overview", "Auditor", "Generator", "Simulator", "Credits"], 
    horizontal=True, 
    label_visibility="collapsed"
)

#PAGE ROUTING
if page == "Overview":
    st.markdown("<h1 class='tile-title'>The Password Safety Suite</h1>", unsafe_allow_html=True)
    st.markdown("<p class='tile-subtitle'>By Sohan Henadeera</p>", unsafe_allow_html=True)
    
    st.markdown("""
<div class='tile-body'>
    <p>A little dashboard to help you and teach you about password security and best practices.</p>
</div>
    """, unsafe_allow_html=True)
    
    #About Section
    st.markdown("""
<div class='tile-card' style='text-align: left; padding: 40px;'>
    <h3 style='margin-top: 0; font-size: 1.4rem;'>About This Dashboard</h3>
    <p style='color: #888; line-height: 1.6; margin-bottom: 30px;'>This interactive web application was built to demonstrate practical, human-centric security principles. Below are some of the features this dashboard contains</p>
    <div style='margin-bottom: 25px;'>
        <h4 style='margin: 0 0 5px 0;'>Password Auditor</h4>
        <p style='margin: 0; color: #888; font-size: 0.95rem; line-height: 1.5;'>Uses a privacy model called <i>k-Anonymity</i> to securely query the Have I Been Pwned API, proving whether a password has been compromised without exposing your actual password to the internet.</p>
    </div>
    <div style='margin-bottom: 25px;'>
        <h4 style='margin: 0 0 5px 0;'>Secure Generator</h4>
        <p style='margin: 0; color: #888; font-size: 0.95rem; line-height: 1.5;'>Uses standard cryptographic libraries to generate high-end passwords that are highly resilient to dictionary and brute-force attacks, while allowing for custom memorable keywords.</p>
    </div>
    <div>
        <h4 style='margin: 0 0 5px 0;'>Cryptographic Simulator</h4>
        <p style='margin: 0; color: #888; font-size: 0.95rem; line-height: 1.5;'>Demonstrates backend server security best practices by illustrating the critical differences between Classical Encryption (reversible) and Modern Hashing (irreversible one-way math).</p>
    </div>
</div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
<div class='tile-card' style='text-align: left; background: rgba(0, 113, 227, 0.05); border: 1px solid rgba(0, 113, 227, 0.2); padding: 40px;'>
    <h3 style='margin-top: 0; color: #0071e3; font-size: 1.4rem;'>💡 Stay Safe: Cybersecurity Tips & Tricks</h3>
    <ul style="padding-left: 20px; margin-bottom: 0; line-height: 1.8;">
        <li><b>Use a Password Manager:</b> Never memorize, write or store your passwords in a public or easy to access place. Let a manager generate and store unique credentials for every site you use. Then securely access them from a encrypted application or a document only you can read/access.</li>
        <li><b>Enable MFA Everywhere:</b> Multi-Factor Authentication stops 99% of automated attacks, even if your password is stolen in a breach.</li>
        <li><b>Watch for Phishing:</b> Always verify the URL before logging in. Attackers fake login screens to steal credentials.</li>
        <li><b>Avoid Reusing Passwords:</b> A breach on an obscure, insecure website can compromise your email, bank or any service where you have reused the same password.</li>
    </ul>
</div>
    """, unsafe_allow_html=True)

elif page == "Auditor":
    st.markdown("<h1 class='tile-title'>Password Auditor</h1>", unsafe_allow_html=True)
    st.markdown("""
    <p class='tile-subtitle'>
        Verify strength and data breach exposure. <br>
        <span style='font-size: 0.9rem; color: #999;'><b>Why it's important:</b> Reusing compromised passwords is the leading cause of account takeovers.</span>
    </p>
    """, unsafe_allow_html=True)
    
    #Fact box
    st.markdown("""
    <div class='tile-fact'>
        <b>💡 Cyber Fact:</b> Over 10 billion credentials have been exposed in public data breaches. Attackers use automated tools to test these leaked passwords across thousands of other websites in seconds, a technique known as <i>Credential Stuffing</i>.
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        user_password = st.text_input("Enter a password to audit:", type="password", key="audit_input", 
                                      help="How to use: Type a password you want to test. We use a privacy technique called k-Anonymity, meaning your full password is NEVER sent over the internet or saved on our side.")

    if user_password:
        pwned_count = check_pwned_api(user_password)
        complexity_score, feedback = check_complexity(user_password)
        crack_time = calculate_time_to_crack(user_password)
        
        st.write("") 
        st.markdown("<h4 style='text-align: center; font-weight: 600;'>Strength Meter</h4>", unsafe_allow_html=True)
        progress_val = complexity_score / 4 
        st.progress(progress_val)
        
        st.markdown(f"<p style='text-align: center; color: #888; font-size: 0.95rem; margin-top: 5px;'>Estimated time to crack (Offline Attack): <b style='color: var(--text-color);'>{crack_time}</b></p>", unsafe_allow_html=True)
        
        if complexity_score == 4:
            st.success("Strength: Very Strong")
        elif complexity_score >= 2:
            st.warning("Strength: Moderate")
        else:
            st.error("Strength: Weak")

        st.markdown("<br>", unsafe_allow_html=True)
        if pwned_count > 0:
            st.error(f"COMPROMISED: This password has been seen in {pwned_count:,} data breaches! Do not use.")
        else:
            st.success("SAFE: This password was not found in any known public data breaches.")
            
        if feedback:
            st.info("Improvement Tips:")
            for item in feedback:
                st.write(f"- {item}")

elif page == "Generator":
    st.markdown("<h1 class='tile-title'>Secure Generator</h1>", unsafe_allow_html=True)
    st.markdown("""
    <p class='tile-subtitle'>
        Create cryptographically secure credentials. <br>
        <span style='font-size: 0.9rem; color: #999;'><b>Why it's important:</b> High-entropy (random) passwords defeat automated brute-force and dictionary attacks.</span>
    </p>
    """, unsafe_allow_html=True)
    
    #Fact box
    st.markdown("""
    <div class='tile-fact'>
        <b>💡 Cyber Fact:</b> Password <b>length</b> is mathematically more important than complexity. Adding a single uppercase letter only slightly increases the character pool, but adding another word or extra characters multiplies the total possible combinations exponentially.
    </div>
    """, unsafe_allow_html=True)
    
    st.write("")
    length = st.slider("Password Total Length", min_value=8, max_value=64, value=16, 
                       help="How to use: Drag the slider to set your total password length. NIST recommends at least 15 characters to defend against modern cracking hardware.")
    
    st.write("")
    col1, col2, col3 = st.columns(3)
    with col1: use_upper = st.checkbox("Uppercase (A-Z)", value=True)
    with col2: use_nums = st.checkbox("Numbers (0-9)", value=True)
    with col3: use_syms = st.checkbox("Symbols (!@#)", value=True)
    
    st.write("")
    col_kw1, col_kw2, col_kw3 = st.columns([1, 2, 1])
    with col_kw2:
        keyword = st.text_input("Include Keyword (Optional)", 
                                help="How to use: Type a word you want to remember (e.g., 'Coffee'). The generator will safely surround it with random characters.")
    
    st.write("")
    button_col1, button_col2, button_col3 = st.columns([1, 1, 1])
    with button_col2:
        generate = st.button("Generate Password", type="primary", use_container_width=True)
        
    if generate:
        new_password = generate_secure_password(length, use_upper, use_nums, use_syms, keyword)
        st.markdown("""
<div class='tile-card'>
    <p style='color: #888; margin-bottom: 10px; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px;'>Generated Credential</p>
    <h2 style='font-family: monospace; letter-spacing: 2px; margin: 0; color: var(--text-color);'>{}</h2>
</div>
        """.format(new_password), unsafe_allow_html=True)
        st.info("Tip: Copy this and paste it into the Auditor tab to test its resilience.")

elif page == "Simulator":
    st.markdown("<h1 class='tile-title'>Cryptographic Simulator</h1>", unsafe_allow_html=True)
    st.markdown("""
    <p class='tile-subtitle'>
        Compare reversible encryption with one-way hashing. <br>
        <span style='font-size: 0.9rem; color: #999;'><b>Why it's important:</b> Understanding how servers store your data helps you recognize secure vs. insecure platforms.</span>
    </p>
    """, unsafe_allow_html=True)
    
    #Fact box
    st.markdown("""
    <div class='tile-fact'>
        <b>💡 Cyber Fact:</b> While SHA-256 is great for verifying data integrity, modern password storage often uses specialized, intentionally "slow" hashing algorithms like <i>Bcrypt</i>, <i>Argon2</i>, or <i>PBKDF2</i>. This makes brute-forcing them extremely computationally expensive and time-consuming for hackers.
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Caesar Cipher (Encryption)", "Secure Storage (Hashing)"])
    
    with tab1:
        st.markdown("""
<div class='tile-body' style='font-size: 0.95rem; color: #888;'>
    <p>The Caesar Cipher is a classic form of <b>Encryption</b> that shifts letters by a fixed number. Because it is easily reversible with the key, it should <b>never</b> be used for passwords but to only hide the true password in your encrypted or safe password document.</p>
</div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            cipher_text = st.text_input("Enter text to encrypt:", 
                                        help="How to use: Type a normal sentence here to see how an ancient cipher scrambles it, and why it's not safe for modern passwords.")
            shift = st.slider("Shift Value", min_value=1, max_value=25, value=3, 
                              help="How to use: Adjust this 'key'. It controls how many places down the alphabet each letter is moved.")
        
        if cipher_text:
            encrypted_text = caesar_cipher(cipher_text, shift)
            
            st.write("")
            st.write("**Step 1: Plain Text:**")
            st.code(cipher_text, language="")
            
            st.write(f"**Step 2: Encrypted Text (Shift {shift}):**")
            st.code(encrypted_text, language="")
            
            st.error("Conclusion: If a hacker knows the shift value, they can easily reverse this and read the original text!")

    with tab2:
        st.markdown("""
<div class='tile-body' style='font-size: 0.95rem; color: #888;'>
    <p>Passwords should never be stored in plain text or encrypted (which is reversible). They should be <b>Hashed</b> (one-way computation) alongside a random string of data called a <b>Salt</b>.</p>
</div>
        """, unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            demo_password = st.text_input("Enter a password to simulate database storage:", 
                                          help="How to use: Type a mock password here to see how a secure database adds a unique 'Salt' and performs a one-way 'Hash' to protect your data.")
        
        if demo_password:
            salt, hashed_result = simulate_hashing(demo_password)
            
            st.write("")
            st.write("**Step 1: Plain Text (What the user types):**")
            st.code(demo_password, language="")
            
            st.write("**Step 2: Cryptographic Salt (Generated by Server):**")
            st.code(salt, language="")
            
            st.write("**Step 3: Final Database Entry (Salt + SHA-256 Hash):**")
            st.code(f"{salt}${hashed_result}", language="")
            
            st.success("Conclusion: Even if a malicious actor steals the database, they cannot reverse this hash back into your original password.")

elif page == "Credits":
    st.markdown("<h1 class='tile-title'>Technologies & Concepts</h1>", unsafe_allow_html=True)
    st.markdown("<p class='tile-subtitle'>Frameworks, libraries, and security models driving this application.</p>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
<div class='tile-card' style='text-align: left; padding: 30px; height: 100%; box-sizing: border-box;'>
    <h3 style='margin-top: 0; margin-bottom: 15px; font-size: 1.3rem;'>Core Tech Stack</h3>
    <ul style="padding-left: 20px; margin-bottom: 25px; line-height: 1.8;">
        <li><b>Language:</b> Python 3</li>
        <li><b>Frontend:</b> Streamlit Framework</li>
        <li><b>Styling:</b> Custom tile-Style CSS</li>
        <li><b>External API:</b> Have I Been Pwned (HIBP)</li>
    </ul>
    <h3 style='margin-top: 0; margin-bottom: 15px; font-size: 1.3rem;'>Python Libraries</h3>
    <ul style="padding-left: 20px; margin-bottom: 0; line-height: 1.8;">
        <li><code>hashlib</code> (SHA-1 & SHA-256)</li>
        <li><code>secrets</code> (CSPRNG generation)</li>
        <li><code>requests</code> (HTTP requests)</li>
        <li><code>re</code> & <code>math</code> (Complexity & Entropy math)</li>
    </ul>
</div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown("""
<div class='tile-card' style='text-align: left; padding: 30px; height: 100%; box-sizing: border-box;'>
    <h3 style='margin-top: 0; margin-bottom: 15px; font-size: 1.3rem;'>Security Concepts</h3>
    <ul style="padding-left: 20px; margin-bottom: 0; line-height: 1.8;">
        <li><b>k-Anonymity:</b> Safe API querying without exposing raw data to the internet.</li>
        <li><b>One-Way Hashing:</b> Irreversible cryptographic hashing for backend data protection.</li>
        <li><b>Cryptographic Salting:</b> Defending against rainbow table attacks.</li>
        <li><b>Classical Encryption:</b> Demonstrating reversible cipher flaws like the Caesar Cipher.</li>
        <li><b>Entropy & Complexity:</b> Mathematical strength calculations against brute-force hardware attacks.</li>
    </ul>
</div>
        """, unsafe_allow_html=True)

    st.markdown("""
<div class='apple-card' style='text-align: left; padding: 30px; margin-top: 20px;'>
    <h3 style='margin-top: 0; margin-bottom: 15px; font-size: 1.3rem;'>Usage & Attribution</h3>
    <p style='color: #888; line-height: 1.6; margin-bottom: 0;'>
        This Password Security Suite is open-source. If you find this code helpful and wish to use, adapt, or build upon it for your own projects, please provide proper attribution by referencing the original author <b>Sohan Henadeera</b> and linking back to the original GitHub repository.
    </p>
</div>
    """, unsafe_allow_html=True)

# --- GLOBAL FOOTER ---
st.markdown("""
<div class="modern-footer">
    <p>&copy; 2026 Sohan Henadeera. All Rights Reserved.</p>
    <p>
        <a href="https://www.linkedin.com/in/sohan-henadeera-155040259/" target="_blank">LinkedIn</a>
        <a href="https://github.com/Sohan-Henadeera" target="_blank">GitHub</a>
        <a href="sohan.henad@gmail.com" target="_blank">Email</a>
    </p>
</div>
""", unsafe_allow_html=True)