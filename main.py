import streamlit as st
import re
import string
import random
import requests
import hashlib
from zxcvbn import zxcvbn
import streamlit.components.v1 as components

# Configure page
st.set_page_config(
    page_title="Password Guardian",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS for clean appearance and improved layouts
st.markdown("""
<style>
    .main {
        max-width: 800px;
        padding: 2rem 1rem;
        margin: 0 auto;
    }
    .header {
        text-align: center;
        margin-bottom: 2.5rem;
    }
    .card {
        background: #ffffff;
        border-radius: 12px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .strength-bar {
        height: 8px;
        border-radius: 4px;
        margin: 1rem 0;
        transition: all 0.3s ease;
    }
    .criteria-list {
        margin: 1rem 0;
        padding-left: 1.2rem;
        display: flex;
        justify-content: flex-end;
        gap: 1rem;
        flex-wrap: wrap;
    }
    .criteria-item {
        display: inline-block;
        background: #f0f0f0;
        padding: 0.3rem 0.6rem;
        border-radius: 12px;
        font-size: 0.9em;
    }
    .generator-options {
        margin: 1rem 0;
        display: flex;
        justify-content: center;
        gap: 1rem;
    }
    .success-badge {
        background: #e8f5e9;
        color: #2e7d32;
        padding: 0.3rem 0.7rem;
        border-radius: 20px;
        font-size: 0.9em;
        border: none;
        cursor: pointer;
    }
    /* Style for the checkbox row */
    .checkbox-row > div {
        flex: 1;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

def check_pwned(password):
    """Check password against Have I Been Pwned database"""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        return suffix in response.text
    except requests.RequestException:
        return False

def analyze_password(password):
    """Comprehensive password analysis using zxcvbn along with manual checks for missing criteria."""
    # Blacklist check for common passwords
    blacklist = {"password123", "admin", "123456", "qwerty", "letmein"}
    if password.lower() in blacklist:
        return {
            'score': 0,
            'warning': "This password is too common and insecure!",
            'suggestions': ["❌ This password is too common and insecure!"],
            'crack_time': "Almost instantly",
            'pwned': False
        }
    
    result = zxcvbn(password)
    suggestions = result['feedback']['suggestions'][:]  # initial suggestions from zxcvbn
    warning = result['feedback']['warning']
    
    # Manual checks (more granular suggestions)
    manual_suggestions = []
    if len(password) < 8:
        manual_suggestions.append("❌ Password should be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        manual_suggestions.append("❌ Include at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        manual_suggestions.append("❌ Include at least one lowercase letter.")
    if not re.search(r"\d", password):
        manual_suggestions.append("❌ Add at least one number (0-9).")
    if not re.search(r"[!@#$%^&*]", password):
        manual_suggestions.append("❌ Include at least one special character (e.g., !@#$%^&*).")
    
    # Append any missing manual suggestion that isn't already provided
    for s in manual_suggestions:
        if s not in suggestions:
            suggestions.append(s)
    
    # If no suggestions exist, indicate the password is strong
    if not suggestions:
        suggestions.append("✅ Excellent! This is a strong password.")
    
    return {
        'score': result['score'],
        'warning': warning,
        'suggestions': suggestions,
        'crack_time': result['crack_times_display']['offline_slow_hashing_1e4_per_second'],
        'pwned': check_pwned(password)
    }

def generate_password(length=16, uppercase=True, lowercase=True, digits=True, symbols=True):
    """Generate secure password with guaranteed complexity"""
    # Default to all options if none are selected
    if not (uppercase or lowercase or digits or symbols):
        uppercase = lowercase = digits = symbols = True

    chars = []
    if uppercase:
        chars.extend(string.ascii_uppercase)
    if lowercase:
        chars.extend(string.ascii_lowercase)
    if digits:
        chars.extend(string.digits)
    if symbols:
        chars.extend("!@#$%^&*")
    
    # Ensure at least one character from each selected type
    password = []
    if uppercase:
        password.append(random.choice(string.ascii_uppercase))
    if lowercase:
        password.append(random.choice(string.ascii_lowercase))
    if digits:
        password.append(random.choice(string.digits))
    if symbols:
        password.append(random.choice("!@#$%^&*"))
    
    # Fill the remaining length
    password += [random.choice(chars) for _ in range(length - len(password))]
    random.shuffle(password)
    return ''.join(password)

def main():
    st.markdown('<div class="main">', unsafe_allow_html=True)
    
    # Header Section
    with st.container():
        st.markdown('<div class="header">', unsafe_allow_html=True)
        st.title("🔒 Password Guardian")
        st.caption("Evaluate password strength and generate secure passwords")
        st.markdown('</div>', unsafe_allow_html=True)

    # Tabs for main functionality
    tab_analyze, tab_generate = st.tabs(["Analyze Password", "Generate Password"])

    with tab_analyze:
        with st.form("analysis_form"):
            password = st.text_input("Enter password to analyze:", 
                                     type="password",
                                     help="We never store or transmit your password")
            submitted = st.form_submit_button("Analyze")
            
        if submitted and password:
            with st.spinner("Checking security..."):
                analysis = analyze_password(password)
                
                # Strength visualization
                colors = ["#ff4444", "#ffbb33", "#00C851", "#00C851"]
                strength = min(analysis['score'], 3)
                st.markdown(f"""
                <div class="card">
                    <h4>Security Analysis</h4>
                    <div class="strength-bar" style="background: {colors[strength]}; width: {(strength + 1) * 25}%"></div>
                    <div class="success-badge">Estimated crack time: {analysis['crack_time']}</div>
                """, unsafe_allow_html=True)
                
                # Security alerts
                if analysis['pwned']:
                    st.error("⚠️ This password has appeared in data breaches!")
                if analysis['warning']:
                    st.warning(f"⚠️ {analysis['warning']}")
                
                # Recommendations rendered as inline checklist on right side
                if analysis['suggestions']:
                    st.markdown("<div class='criteria-list'>", unsafe_allow_html=True)
                    for suggestion in analysis['suggestions']:
                        st.markdown(f"<span class='criteria-item'>✏️ {suggestion}</span>", unsafe_allow_html=True)
                    st.markdown("</div>", unsafe_allow_html=True)
                
                st.markdown("</div>", unsafe_allow_html=True)

    with tab_generate:
        with st.form("generation_form"):
            length = st.slider("Password length", 12, 32, 16)
            # Use columns for a one-line layout of checkboxes
            cols = st.columns(4)
            uppercase = cols[0].checkbox("Uppercase letters", True)
            lowercase = cols[1].checkbox("Lowercase letters", True)
            digits = cols[2].checkbox("Numbers", True)
            symbols = cols[3].checkbox("Include symbols", True)
            generate = st.form_submit_button("Generate Password")
        
        if generate:
            new_password = generate_password(length, uppercase, lowercase, digits, symbols)
            st.markdown(f"""
            <div class="card">
                <h4>Generated Password</h4>
                <code style="font-size: 1.4rem">{new_password}</code>
            </div>
            """, unsafe_allow_html=True)
            # Render an HTML block with a copy button that shows an animation on click
            components.html(f"""
            <html>
              <body style="display: flex; justify-content: center; align-items: center; height: 120px;">
                <button id="copyBtn" onclick="copyText()"
                        style="background: #e8f5e9; color: #2e7d32; padding: 0.5rem 1rem; border-radius: 20px; font-size: 1em; border: none; cursor: pointer; transition: background 0.3s ease;">
                    Copy to Clipboard
                </button>
                <script>
                  function copyText() {{
                    var btn = document.getElementById("copyBtn");
                    navigator.clipboard.writeText("{new_password}").then(function() {{
                      btn.innerText = "Copied!";
                      btn.style.background = "#00C851";
                      setTimeout(function(){{
                        btn.innerText = "Copy to Clipboard";
                        btn.style.background = "#e8f5e9";
                      }}, 2000);
                    }});
                  }}
                </script>
              </body>
            </html>
            """, height=120)

    # Footer
    st.markdown("---")
    st.caption("🔐 Passwords are processed locally and never stored • v1.0")
    st.markdown('</div>', unsafe_allow_html=True)

if __name__ == "__main__":
    main()
