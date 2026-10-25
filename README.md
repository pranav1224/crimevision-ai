# CrimeVision AI — Intelligent Multimodal Forensic Analysis Platform
**Skill Wallet & FutureSkills Prime — Capstone Project 2**  
*Platform ID: `6ac4c9851dcde6d7857c163b` | Category: Generative AI, Criminal Justice & Public Safety*

---

## 📌 Executive Summary
**CrimeVision AI** is an end-to-end, production-ready forensic intelligence application that fuses multimodal evidence across crime scene imagery, emergency dispatch/witness audio, and CCTV surveillance footage. It reconstructs chronological crime progressions, maps statutory penal code violations, enables grounded zero-hallucination conversational interrogation (RAG) with mandatory Evidence ID citations, and exports court-admissible PDF reports certified under Federal Rules of Evidence (FRE) 901/902.

---

## 🏛️ Core Architecture & Kanban Epics Coverage

| Module / Epic | Technology / Standard | Evidentiary Role |
| :--- | :--- | :--- |
| **Epic 1: Security & Chain of Custody** | SHA-256 Hashes, FRE 901/902 | Cryptographic integrity ledger, Evidence ID tracking, and Investigator sign-off. |
| **Epic 2: Visual Evidence Tagger (Tab 1)** | RT-DETR Simulation, PIL HUD | Detects persons, firearms, edged weapons, blood spatter, forced entry points with normalized bounding boxes. |
| **Epic 3: Audio Transcription & Timeline (Tab 2)** | Whisper Large-v3 / Forensic VAD | Verbatim speech-to-text, speaker diarization, vocal urgency tracking, and timestamped markers. |
| **Epic 4: CCTV Video & Penal Events (Tab 3)** | OpenCV Keyframe Sampling | Tracks suspect & vehicle trajectory vectors across seconds; classifies statutory penal crimes (§459, §211, §245(a)(2)). |
| **Epic 5: Multimodal Fusion & Grounded Chat (Tab 4)** | Master Event Ledger & RAG | Aligns all media timestamps into a unified ledger; natural language interrogation citing Evidence IDs with zero hallucination. |
| **Epic 6: Automated PDF Export (Tab 5)** | ReportLab Platypus Engine | 1-Click generation of formal court-admissible PDF summaries with digital certification blocks. |

---

## 🚀 Quickstart & Local Execution

### 1. Prerequisites
- Python 3.9, 3.10, 3.11, 3.12, 3.13, or 3.14
- Virtual environment (recommended)

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 🌐 Deployment Guide (Render & Streamlit Cloud)

### Part A: Upload to GitHub (Choose Any Method)

#### Method 1: Instant Web Upload (No Git Installation Needed)
1. Go to [github.com/new](https://github.com/new) and create a repository named `crimevision-ai` (set to **Public**).
2. On the new repository page, click **uploading an existing file**.
3. Drag and drop all files and folders from `C:\Users\hp\.gemini\antigravity\scratch\crimevision-ai`.
4. Click **Commit changes**.

#### Method 2: 1-Click Python Uploader Script
Run in PowerShell:
```powershell
python upload_to_github.py <YOUR_GITHUB_PERSONAL_ACCESS_TOKEN>
```

#### Method 3: Standard Git CLI (if Git is installed)
```bash
git init
git add .
git commit -m "feat: CrimeVision AI production multimodal forensic platform"
git branch -M main
git remote add origin https://github.com/<your-username>/crimevision-ai.git
git push -u origin main
```

---

### Part B: Deploy to Render (100% Free)

1. Sign up / Log into [Render.com](https://render.com).
2. Click **New +** and select **Web Service**.
3. Connect your GitHub account and select your `crimevision-ai` repository.
4. Configure the Web Service settings:
   - **Name**: `crimevision-ai`
   - **Language**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true`
   - **Plan**: `Free`
5. Click **Deploy Web Service**.
6. Render will build and deploy the app, providing a live HTTPS URL:
   `https://crimevision-ai.onrender.com`

---

### Part C: Deploy to Streamlit Community Cloud (Alternative 60-Second Hosting)

1. Go to [share.streamlit.io](https://share.streamlit.io) and log in with GitHub.
2. Click **New app**.
3. Select your repository `crimevision-ai`, branch `main`, and main file path `app.py`.
4. Click **Deploy!**
5. Get your live URL: `https://crimevision-ai.streamlit.app`.

---

## 📋 Skill Wallet Steps 33 & 34 Submission Guide

1. **Step 33 (GitHub Repository Link)**:
   - Paste your public GitHub URL: `https://github.com/<your-username>/crimevision-ai`.
   - Click **Update GitHub Link**.

2. **Step 34 (Live Hosted Demo Link)**:
   - Paste your live Render URL (`https://crimevision-ai.onrender.com`) or Streamlit Cloud URL (`https://crimevision-ai.streamlit.app`).
   - Click **Update Demo Link**.

3. **Step 35 (Claim NASSCOM Certificate)**:
   - Go to Tab `5. Certificate` on Skill Wallet. The 3 criteria will turn green, allowing you to instantly download your official accredited certificate!
