import os
import hashlib
import math
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import Counter
import streamlit as st
from mpl_toolkits.mplot3d import Axes3D  # For 3D plotting

# ------------------ Core Functions ------------------

def kyber_keygen():
    public_key = os.urandom(32)
    secret_key = os.urandom(32)
    return public_key, secret_key

def derive_shared_secret(message, public_key):
    combined = message.encode() + public_key
    return hashlib.sha256(combined).hexdigest()

def kyber_encapsulate(public_key, message):
    ciphertext = os.urandom(64)
    shared_secret = derive_shared_secret(message, public_key)
    return ciphertext, shared_secret

def kyber_decapsulate(ciphertext, secret_key, message, public_key):
    return derive_shared_secret(message, public_key)

def calculate_entropy(data):
    counter = Counter(data)
    total = len(data)
    return round(-sum((count / total) * math.log2(count / total) for count in counter.values()), 2)

# ------------------ Streamlit UI ------------------

st.set_page_config(page_title="Kyber KEM Visualization", page_icon="🔐")

st.markdown("""
    <style>
        body {
            background-color: #121212;
            color: white;
        }
        .css-1d391kg, .stTextInput input, .stDownloadButton button {
            color: white !important;
            background-color: #333 !important;
        }
        .stButton>button {
            color: white !important;
            background-color: #444 !important;
        }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Kyber KEM Simulation")
st.caption("Post-Quantum Key Exchange + Visualization Demo")

# Info
with st.expander("ℹ️ About Kyber"):
    st.markdown("Kyber is a post-quantum cryptographic algorithm that uses lattice-based mathematics to create secure keys. Unlike RSA or ECC, which can be broken by Shor's algorithm running on quantum computers, Kyber's security is based on the hardness of the module learning with errors (M-LWE) problem, which is believed to be resistant to both classical and quantum attacks. It was selected by NIST in 2022 as the first standardized post-quantum key encapsulation mechanism and will likely become the backbone of secure communications in the quantum era.")

# Step 1: Key Generation
st.header("🧬 Step 1: Key Generation")

if st.button("🔁 Generate Key Pair"):
    pk, sk = kyber_keygen()
    st.session_state['pk'] = pk
    st.session_state['sk'] = sk
    st.success("Key pair generated!")

if 'pk' in st.session_state:
    st.code(f"Public Key: {st.session_state['pk'].hex()}")
    st.code(f"Secret Key: {st.session_state['sk'].hex()}")

# Step 2: Message Input
st.header("✉️ Step 2: Enter Message")
message = st.text_input("Enter your secure message:")

# Step 3: Encryption + Decryption
if message and 'pk' in st.session_state:
    ct, ss_sender = kyber_encapsulate(st.session_state['pk'], message)
    ss_receiver = kyber_decapsulate(ct, st.session_state['sk'], message, st.session_state['pk'])

    st.header("🔐 Step 3: Shared Secret Exchange")
    st.code(f"Ciphertext (truncated): {ct.hex()[:64]}...")
    st.code(f"Shared Secret (Sender): {ss_sender}")
    st.code(f"Shared Secret (Receiver): {ss_receiver}")

    match = ss_sender == ss_receiver
    if match:
        st.success("✅ Shared secrets match!")
    else:
        st.error("❌ Shared secrets do not match!")

    # 📊 Visualization Section
    st.header("📊 Visualizations")

    # 1. Entropy Bar Chart
    entropy = calculate_entropy(ss_sender)
    fig1, ax1 = plt.subplots()
    ax1.barh(["Shared Secret"], [entropy], color="#00C49F")
    ax1.set_xlim(0, 8)
    ax1.set_xlabel("Entropy (bits per char)")
    ax1.set_title("Shared Secret Entropy")
    st.pyplot(fig1)

    # 2. Heatmap of Shared Secret Characters
    st.subheader("🔳 Shared Secret Heatmap (Visual Randomness)")
    byte_values = [int(c, 16) for c in ss_sender[:64]]  # First 64 hex chars
    grid = np.array(byte_values).reshape(8, 8)
    fig2, ax2 = plt.subplots()
    sns.heatmap(grid, cmap="viridis", linewidths=0.5, annot=True, fmt="d", cbar=False, ax=ax2)
    st.pyplot(fig2)

    # 3. Pie Chart: Ciphertext vs Shared Secret Size
    st.subheader("🥧 Size Comparison")
    sizes = [len(ct), len(ss_sender)]
    labels = ["Ciphertext", "Shared Secret"]
    fig3, ax3 = plt.subplots()
    ax3.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=["#FF6F61", "#6A5ACD"])
    ax3.axis("equal")
    st.pyplot(fig3)

    # 4. 3D Byte Distribution Plot
    st.subheader("📊 3D Byte Distribution of Shared Secret")
    hex_pairs = [ss_sender[i:i+2] for i in range(0, min(len(ss_sender), 60), 2)]
    byte_values_3d = np.array([int(h, 16) for h in hex_pairs])
    byte_values_3d = byte_values_3d[:len(byte_values_3d) - len(byte_values_3d) % 3].reshape(-1, 3)
    fig4 = plt.figure()
    ax4 = fig4.add_subplot(111, projection='3d')
    ax4.scatter(byte_values_3d[:, 0], byte_values_3d[:, 1], byte_values_3d[:, 2], color="cyan")
    ax4.set_xlabel('Byte 1')
    ax4.set_ylabel('Byte 2')
    ax4.set_zlabel('Byte 3')
    ax4.set_title("3D Byte Distribution of Shared Secret")
    st.pyplot(fig4)

    # 5. Byte Distribution Bar Graph
    st.subheader("📊 Byte Distribution Bar Graph")
    byte_counter = Counter([int(c, 16) for c in ss_sender[:64]])  # First 64 bytes
    byte_labels, byte_counts = zip(*byte_counter.items())
    fig5, ax5 = plt.subplots()
    ax5.bar(byte_labels, byte_counts, color="#FF914D")
    ax5.set_xlabel("Byte Value")
    ax5.set_ylabel("Frequency")
    ax5.set_title("Byte Value Distribution in Shared Secret")
    st.pyplot(fig5)

# Footer
st.markdown("---")
st.caption("This is the final Results with the graphs")

