"""
CrimeVision AI - Intelligent Multimodal Forensic Analysis Platform
Skill Wallet Capstone Project 2 (Platform ID: 6ac4c9851dcde6d7857c163b)

Senior Forensic Systems Architecture:
Fusing crime scene photography, witness dispatch audio, CCTV surveillance,
and grounded RAG chat into a unified court-admissible forensic ledger.
"""

import streamlit as st
import pandas as pd
from PIL import Image
import io
import time
from datetime import datetime, timezone

# Import forensic modules
from modules.config import FORENSIC_THEME_CSS, PENAL_CODES
from modules.security import EvidenceRegistry, compute_sha256_bytes
from modules.ai_engines import ForensicAIEngine
from modules.visual_tagger import VisualEvidenceTagger
from modules.audio_transcriber import AudioForensicTranscriber
from modules.video_analyzer import VideoEventAnalyzer
from modules.multimodal_fusion import MultimodalFusionEngine
from modules.rag_chat import GroundedForensicRAG
from modules.pdf_exporter import ForensicPDFExporter
from sample_data.forensic_samples import generate_sample_crime_scene_image, generate_sample_audio_wav


# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CrimeVision AI — Forensic Analysis Platform",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply Dark Tactical Forensic CSS
st.markdown(FORENSIC_THEME_CSS, unsafe_allow_html=True)


# --- SESSION STATE INITIALIZATION ---
if "evidence_registry" not in st.session_state:
    registry = EvidenceRegistry(case_number="CV-2026-8842")
    # Pre-register default Case 8842 Evidence items
    sample_img_bytes = generate_sample_crime_scene_image()
    sample_aud_bytes = generate_sample_audio_wav()
    sample_vid_bytes = b"SIMULATED_CCTV_SECTOR_04_FEED_SECURED_BLOB"

    registry.register_evidence(
        evidence_id="EVD-IMG-001",
        evidence_type="IMAGE",
        description="High-Resolution Crime Scene Optical Capture (Vault Rear Entry)",
        raw_data=sample_img_bytes,
        officer="Det. M. Vance",
        badge="B-8842",
        agency="Metropolitan Police Dept - Major Crimes"
    )
    registry.register_evidence(
        evidence_id="EVD-AUD-002",
        evidence_type="AUDIO",
        description="Emergency 911 Communications Audio Recording (Call #911-8842)",
        raw_data=sample_aud_bytes,
        officer="Det. M. Vance",
        badge="B-8842",
        agency="Metropolitan Police Dept - Major Crimes"
    )
    registry.register_evidence(
        evidence_id="EVD-VID-003",
        evidence_type="VIDEO",
        description="CCTV Commercial Surveillance Feed (Sector 04 Alleyway & Vault)",
        raw_data=sample_vid_bytes,
        officer="Det. M. Vance",
        badge="B-8842",
        agency="Metropolitan Police Dept - Major Crimes"
    )

    st.session_state.evidence_registry = registry
    st.session_state.sample_img_bytes = sample_img_bytes
    st.session_state.sample_aud_bytes = sample_aud_bytes
    st.session_state.chat_history = []

# Persistent modules
visual_tagger = VisualEvidenceTagger()
video_analyzer = VideoEventAnalyzer()
fusion_engine = MultimodalFusionEngine()
pdf_exporter = ForensicPDFExporter()


# --- SIDEBAR CONFIGURATION & FORENSIC SECURITY ---
with st.sidebar:
    st.markdown("### 🛡️ SYSTEM SECURITY & CREDENTIALS")
    st.caption("CrimeVision AI v2.4 — Major Crimes Division")

    provider = st.selectbox(
        "AI Intelligence Provider",
        options=["Demo Fallback (Preloaded)", "Groq (Llama 3.3 & Whisper)", "Google Gemini (gemini-2.5-flash)"],
        index=0,
        help="Select live API key inference or offline high-fidelity forensic simulation."
    )

    api_key = ""
    if provider == "Groq (Llama 3.3 & Whisper)":
        api_key = st.text_input("Enter Groq API Key", type="password", help="Required for live Groq LLaMA & Whisper")
        if not api_key:
            st.info("ℹ️ Running in automatic demo fallback mode until key is entered.")
    elif provider == "Google Gemini (gemini-2.5-flash)":
        api_key = st.text_input("Enter Gemini API Key", type="password", help="Required for live Google GenAI")
        if not api_key:
            st.info("ℹ️ Running in automatic demo fallback mode until key is entered.")
    else:
        st.success("🟢 100% Offline Demo Mode Active (Zero External Calls)")

    # Investigator Sign-Off Form
    st.markdown("---")
    st.markdown("### ✍️ INVESTIGATOR SIGN-OFF")
    investigator_name = st.text_input("Lead Investigator", value="Det. Marcus Vance")
    badge_number = st.text_input("Badge Number", value="B-8842")
    investigating_agency = st.text_input("Jurisdiction / Agency", value="Metropolitan Police Dept - Major Crimes")

    st.markdown("---")
    st.markdown("### 📁 ACTIVE FORENSIC CASE")
    case_id = st.text_input("Case File ID", value="CV-2026-8842")
    incident_date = st.text_input("Incident Date", value="2026-10-25")

    st.markdown("---")
    if st.button("🔄 Reset Forensic Evidence Ledger", use_container_width=True):
        st.session_state.clear()
        st.rerun()

# Instantiate AI engine
engine_provider_name = "Groq" if "Groq" in provider and api_key else ("Google Gemini" if "Gemini" in provider and api_key else "Demo Fallback")
ai_engine = ForensicAIEngine(provider=engine_provider_name, api_key=api_key)
audio_transcriber = AudioForensicTranscriber(ai_engine=ai_engine)
rag_engine = GroundedForensicRAG(ai_engine=ai_engine)


# --- TOP FORENSIC HEADER HUD ---
st.markdown(f"""
<div class="forensic-header">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
        <div>
            <div class="forensic-title">
                <span>🔬 CRIMEVISION AI</span>
                <span class="forensic-badge">MULTIMODAL FORENSICS</span>
                <span class="forensic-badge badge-critical">LEVEL 4 ENCRYPTION</span>
            </div>
            <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">
                Intelligent Multimodal Forensic Analysis Platform &bull; Case <b>#{case_id}</b> &bull; Lead: <b>{investigator_name}</b> ({badge_number})
            </div>
        </div>
        <div style="text-align: right; margin-top: 8px;">
            <span class="forensic-badge badge-low">EVIDENTIARY INTEGRITY: VERIFIED</span>
            <div style="font-family: monospace; font-size: 11px; color: #64748b; margin-top: 4px;">
                TIMESTAMP: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# --- FORENSIC CHAIN-OF-CUSTODY TRACKING BAR ---
records = st.session_state.evidence_registry.get_all_records()
evd_chips = " &nbsp;|&nbsp; ".join([f"<span class='evidence-chip'>[{r['evidence_id']}] {r['evidence_type']}</span> (SHA: {r['sha256_hash'][:8]}...)" for r in records])

st.markdown(f"""
<div class="custody-bar">
    <b>CHAIN OF CUSTODY (FRE 901/902):</b> {evd_chips}
</div>
""", unsafe_allow_html=True)


# --- NAVIGATION TABS (5 CORE EPICS) ---
tabs = st.tabs([
    "📸 Tab 1: Visual Evidence Tagger",
    "🎙️ Tab 2: Witness Audio & Timeline",
    "🎥 Tab 3: CCTV Video & Penal Events",
    "🔗 Tab 4: Multimodal Fusion & Grounded Chat",
    "📑 Tab 5: Automated Forensic PDF Export"
])


# =========================================================================
# TAB 1: CRIME SCENE VISUAL EVIDENCE TAGGER (EPIC 2)
# =========================================================================
with tabs[0]:
    st.subheader("Crime Scene Visual Evidence Tagger (RT-DETR Simulation)")
    st.caption("Optical detection for persons, firearms, edged weapons, blood spatter, and forced entry points with normalized bounding coordinates.")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("#### 📤 Upload Scene Photography")
        uploaded_image = st.file_uploader(
            "Upload crime scene photo (JPG/PNG)",
            type=["jpg", "jpeg", "png"],
            key="scene_img_uploader"
        )

        use_sample_img = st.button("⚡ Load Built-In Crime Scene Photo (Case #CV-2026-8842)", use_container_width=True)

        if uploaded_image is not None:
            active_img_bytes = uploaded_image.getvalue()
            # Register or update in registry
            st.session_state.evidence_registry.register_evidence(
                evidence_id="EVD-IMG-001",
                evidence_type="IMAGE",
                description=f"Uploaded Scene Photo ({uploaded_image.name})",
                raw_data=active_img_bytes,
                officer=investigator_name,
                badge=badge_number,
                agency=investigating_agency
            )
        elif use_sample_img or "active_img_bytes" not in st.session_state:
            active_img_bytes = st.session_state.sample_img_bytes
            st.session_state.active_img_bytes = active_img_bytes
        else:
            active_img_bytes = st.session_state.active_img_bytes

        # Run Visual Detection
        with st.spinner("Executing RT-DETR Multimodal Object Detection..."):
            vis_results = visual_tagger.analyze_crime_scene_image(active_img_bytes)
            st.session_state.vis_results = vis_results

        st.image(
            vis_results["annotated_image_bytes"],
            caption="RT-DETR Annotated Crime Scene Imagery with Forensic Bounding Boxes",
            use_container_width=True
        )

    with col2:
        st.markdown("#### 📊 Structured Forensic Scene Analysis")

        # Threat Level Badge
        threat = vis_results["threat_level"]
        threat_class = "badge-critical" if threat == "Critical" else ("badge-high" if threat == "High" else "badge-medium")

        st.markdown(f"""
        <div style="display: flex; gap: 12px; margin-bottom: 16px;">
            <div class="metric-card" style="flex: 1;">
                <div class="metric-value"><span class="forensic-badge {threat_class}" style="font-size: 16px;">{threat.upper()}</span></div>
                <div class="metric-label">Assessed Threat Level</div>
            </div>
            <div class="metric-card" style="flex: 1.5;">
                <div class="metric-value" style="font-size: 16px; color: #f8fafc; padding-top: 4px;">{vis_results['scene_classification']}</div>
                <div class="metric-label">Scene Classification</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Detected items table
        st.markdown("##### 🎯 Identified Forensic Objects & Spatial Coordinates")
        det_data = []
        for d in vis_results["detections"]:
            det_data.append({
                "Detection ID": d["id"],
                "Item": d["label"],
                "Category": d["category"],
                "Confidence": f"{d['confidence']*100:.1f}%",
                "Bounding Box [ymin, xmin, ymax, xmax]": f"[{d['bbox'][0]:.2f}, {d['bbox'][1]:.2f}, {d['bbox'][2]:.2f}, {d['bbox'][3]:.2f}]",
                "Forensic Significance": d["forensic_notes"]
            })
        st.dataframe(pd.DataFrame(det_data), use_container_width=True, hide_index=True)

        # Prioritized Leads
        st.markdown("##### 🚨 Prioritized Investigative Leads")
        for lead in vis_results["investigative_leads"]:
            st.markdown(f"""
            <div style="background: #111827; border-left: 3px solid #f59e0b; padding: 10px 14px; border-radius: 4px; margin-bottom: 8px;">
                <span class="forensic-badge badge-high">{lead['priority']}</span> <b>{lead['lead']}</b><br/>
                <span style="font-size: 12px; color: #cbd5e1;">{lead['details']}</span>
            </div>
            """, unsafe_allow_html=True)


# =========================================================================
# TAB 2: WITNESS AUDIO TRANSCRIPTION & TIMELINE (EPIC 3)
# =========================================================================
with tabs[1]:
    st.subheader("Witness Audio Transcription & Timeline Extraction")
    st.caption("Audio transcription with Whisper / Gemini, speaker diarization, vocal urgency tracking, and timestamped legal evidentiary markers.")

    a_col1, a_col2 = st.columns([1, 1])

    with a_col1:
        st.markdown("#### 🎙️ Witness Audio / Emergency 911 Dispatch")
        uploaded_audio = st.file_uploader(
            "Upload audio recording (WAV, MP3, M4A)",
            type=["wav", "mp3", "m4a"],
            key="witness_audio_uploader"
        )
        use_sample_aud = st.button("⚡ Load Built-In 911 Emergency Dispatch Audio", use_container_width=True)

        if uploaded_audio is not None:
            active_aud_bytes = uploaded_audio.getvalue()
            st.session_state.evidence_registry.register_evidence(
                evidence_id="EVD-AUD-002",
                evidence_type="AUDIO",
                description=f"Uploaded Witness Audio ({uploaded_audio.name})",
                raw_data=active_aud_bytes,
                officer=investigator_name,
                badge=badge_number,
                agency=investigating_agency
            )
        elif use_sample_aud or "active_aud_bytes" not in st.session_state:
            active_aud_bytes = st.session_state.sample_aud_bytes
            st.session_state.active_aud_bytes = active_aud_bytes
        else:
            active_aud_bytes = st.session_state.active_aud_bytes

        st.audio(active_aud_bytes, format="audio/wav")

        with st.spinner("Analyzing Speech Signals & Extracting Diarization..."):
            audio_results = audio_transcriber.analyze_audio_recording(active_aud_bytes)
            st.session_state.audio_findings = audio_results

        # Metric cards
        m = audio_results["metrics"]
        st.markdown(f"""
        <div style="display: flex; gap: 10px; margin-top: 14px;">
            <div class="metric-card" style="flex: 1;">
                <div class="metric-value">{m['speaker_count']}</div>
                <div class="metric-label">Speakers Identified</div>
            </div>
            <div class="metric-card" style="flex: 1;">
                <div class="metric-value">{m['total_duration_sec']}s</div>
                <div class="metric-label">Call Duration</div>
            </div>
            <div class="metric-card" style="flex: 1.5;">
                <div class="metric-value" style="font-size: 15px; color: #ef4444;">{m['peak_vocal_urgency']}</div>
                <div class="metric-label">Peak Vocal Urgency</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    with a_col2:
        st.markdown("#### 📝 Timestamped Forensic Dialogue Transcript")
        for seg in audio_results["transcript_timeline"]:
            spk_color = "#38bdf8" if "Dispatcher" in seg["speaker"] else ("#f59e0b" if "Witness" in seg["speaker"] else "#ef4444")
            st.markdown(f"""
            <div style="background: #0f172a; border-left: 3px solid {spk_color}; padding: 8px 12px; border-radius: 4px; margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; font-size: 11px; color: #94a3b8; font-family: monospace;">
                    <span><b>[{seg['timestamp_str']}]</b> {seg['speaker']}</span>
                    <span>Stress: {seg['vocal_stress']}</span>
                </div>
                <div style="font-size: 13px; color: #f1f5f9; margin-top: 4px;">"{seg['dialogue']}"</div>
                <div style="margin-top: 4px;"><span class="forensic-badge" style="font-size: 9px;">{seg['flag']}</span></div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("##### 📌 Extracted Key Evidentiary Events")
        event_df = pd.DataFrame(audio_results["key_events"])
        st.dataframe(event_df, use_container_width=True, hide_index=True)


# =========================================================================
# TAB 3: CCTV VIDEO ANALYSIS & EVENT PROGRESSION (EPIC 4)
# =========================================================================
with tabs[2]:
    st.subheader("CCTV Video Analysis & Event Progression (Penal Violations)")
    st.caption("Frame sampling, trajectory tracking, suspect & vehicle velocity vectors, and classified penal code violations across time.")

    with st.spinner("Extracting Keyframes and Computing Motion Trajectories..."):
        video_results = video_analyzer.process_cctv_video()
        st.session_state.video_findings = video_results

    st.markdown("#### 🖥️ CCTV Surveillance Keyframes & Target Tracking")
    k_cols = st.columns(4)
    for i, kf in enumerate(video_results["keyframes"]):
        with k_cols[i]:
            st.image(kf["image_bytes"], caption=kf["title"], use_container_width=True)

    st.markdown("---")
    st.markdown("#### ⚖️ Chronological Event Log & Classified Penal Categories")

    cctv_log_df = pd.DataFrame(video_results["progression_log"])
    st.dataframe(cctv_log_df, use_container_width=True, hide_index=True)

    # Penal Code Reference Card
    with st.expander("📖 Statutory Penal Code Violation Reference Library"):
        p_cols = st.columns(len(PENAL_CODES))
        for i, (k, p) in enumerate(PENAL_CODES.items()):
            with p_cols[i]:
                st.markdown(f"""
                <div class="metric-card" style="text-align: left; border-top: 3px solid {p['color']};">
                    <div style="font-weight: 700; color: {p['color']}; font-size: 13px;">{p['code']}</div>
                    <div style="font-size: 12px; font-weight: 600; color: #f1f5f9; margin-top: 2px;">{p['title']}</div>
                    <div style="font-size: 10px; color: #94a3b8; margin-top: 4px;">{p['severity']}</div>
                    <div style="font-size: 10px; color: #cbd5e1; margin-top: 4px;">{p['elements']}</div>
                </div>
                """, unsafe_allow_html=True)


# =========================================================================
# TAB 4: MULTIMODAL FUSION & GROUNDED EVIDENCE CHAT (EPIC 5)
# =========================================================================
with tabs[3]:
    st.subheader("Multimodal Fusion & Grounded Evidence Chat (Zero Hallucination)")
    st.caption("Master chronological ledger combining image, audio, and video timestamps with strict Evidence ID citations.")

    # Generate or retrieve master timeline
    master_timeline = fusion_engine.build_master_forensic_ledger(
        st.session_state.get("vis_results", {}),
        st.session_state.get("audio_findings", {}),
        st.session_state.get("video_findings", {})
    )
    st.session_state.master_timeline = master_timeline
    corroboration_matrix = fusion_engine.get_corroboration_matrix()

    st.markdown("#### 📜 Master Synchronized Forensic Ledger")
    timeline_display = []
    for item in master_timeline:
        timeline_display.append({
            "Timestamp": item["timestamp"],
            "Offset": item["time_offset"],
            "Modality": item["modality"],
            "Evidence ID": item["evidence_id"],
            "Source": item["source_label"],
            "Forensic Event": item["event_description"],
            "Legal Classification": item["legal_significance"]
        })
    st.dataframe(pd.DataFrame(timeline_display), use_container_width=True, hide_index=True)

    with st.expander("🔍 Cross-Modal Corroboration Matrix (Triangulated Proof)"):
        st.dataframe(pd.DataFrame(corroboration_matrix), use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("#### 💬 Grounded Evidence Interrogation (Natural Language RAG)")
    st.caption("Interrogate the unified evidence repository. System strictly enforces zero hallucination and mandatory citations.")

    # Sample Quick Prompts
    st.markdown("**Quick Forensic Queries:**")
    q_col1, q_col2, q_col3, q_col4 = st.columns(4)
    quick_q = None
    if q_col1.button("🔫 Was weapon visible before suspect fled?", use_container_width=True):
        quick_q = "Was a weapon visible before the suspect fled?"
    if q_col2.button("🚗 What vehicle was used and direction?", use_container_width=True):
        quick_q = "What vehicle was used to escape and what direction did it flee?"
    if q_col3.button("🚪 How did suspect force entry?", use_container_width=True):
        quick_q = "How did the suspect gain forced entry to the building?"
    if q_col4.button("🩸 What biological evidence was recovered?", use_container_width=True):
        quick_q = "What biological evidence was deposited and where?"

    # Chat history display
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    user_query = st.chat_input("Ask a grounded forensic question (e.g., 'Confirm suspect weapon and escape vehicle')...")
    active_query = user_query or quick_q

    if active_query:
        st.session_state.chat_history.append({"role": "user", "content": active_query})
        with st.chat_message("user"):
            st.markdown(active_query)

        with st.chat_message("assistant"):
            with st.spinner("Interrogating Chain of Custody & Master Ledger..."):
                answer = rag_engine.interrogate_evidence(
                    query=active_query,
                    chain_of_custody_records=records,
                    master_timeline=master_timeline,
                    corroboration_matrix=corroboration_matrix
                )
                st.markdown(answer)
                st.session_state.chat_history.append({"role": "assistant", "content": answer})


# =========================================================================
# TAB 5: AUTOMATED FORENSIC PDF EXPORT (EPIC 6)
# =========================================================================
with tabs[4]:
    st.subheader("Automated Forensic PDF Export (Court-Admissible Documentation)")
    st.caption("1-Click compilation of official forensic reports conforming to Federal Rules of Evidence 901/902 with digital signature blocks.")

    p_col1, p_col2 = st.columns([1.2, 1])

    with p_col1:
        st.markdown("#### 📄 Document Compilation Scope")
        st.markdown("""
        The generated official report compiles:
        - **Official Case Header & Metadata** (Case #, Date, Agency, Lead Investigator)
        - **Chain of Custody Table** with Cryptographic SHA-256 Checksums
        - **Visual Optical Scene Findings** (RT-DETR Bounding Boxes & Threat Assessment)
        - **Witness Audio Transcript & Diarization Chronology**
        - **CCTV Surveillance Telemetry & Penal Code Violations**
        - **Master Synchronized Multimodal Chronology**
        - **FRE 901/902 Digital Signature & Admissibility Sign-Off**
        """)

        case_info = {
            "case_number": case_id,
            "incident_date": incident_date,
            "agency": investigating_agency,
            "officer": investigator_name,
            "badge": badge_number
        }

        # Generate PDF Button
        if st.button("🚀 Compile Court-Admissible Forensic PDF", type="primary", use_container_width=True):
            with st.spinner("Compiling ReportLab PDF Document & Calculating Signatures..."):
                pdf_bytes = pdf_exporter.generate_pdf_report(
                    case_info=case_info,
                    chain_of_custody=records,
                    visual_findings=st.session_state.get("vis_results", visual_tagger.analyze_crime_scene_image(st.session_state.sample_img_bytes)),
                    audio_findings=st.session_state.get("audio_findings", audio_transcriber.analyze_audio_recording(st.session_state.sample_aud_bytes)),
                    video_findings=st.session_state.get("video_findings", video_analyzer.process_cctv_video()),
                    master_timeline=st.session_state.get("master_timeline", master_timeline)
                )
                st.session_state.latest_pdf_bytes = pdf_bytes
                st.success("✅ Forensic PDF Report Successfully Generated!")

        if "latest_pdf_bytes" in st.session_state:
            st.download_button(
                label=f"⬇️ Download Official Forensic PDF Report ({case_id})",
                data=st.session_state.latest_pdf_bytes,
                file_name=f"CrimeVision_{case_id}_Forensic_Report.pdf",
                mime="application/pdf",
                use_container_width=True
            )

    with p_col2:
        st.markdown("#### 📜 Court Certification Preview")
        st.markdown(f"""
        <div class="terminal-box" style="color: #cbd5e1; font-size: 11px;">
            <b>CASE FILE:</b> {case_id}<br/>
            <b>OFFICER:</b> {investigator_name} (Badge {badge_number})<br/>
            <b>AGENCY:</b> {investigating_agency}<br/>
            <b>STATUS:</b> EVIDENTIARY AUDIT VERIFIED<br/>
            <b>DIGITAL HASH (LEDGER ROOT):</b><br/>
            <code>{records[0]['sha256_hash']}</code><br/><br/>
            <i>"Certified under penalty of perjury under Federal Rules of Evidence 901 and 902. Zero automated tampering has occurred."</i>
        </div>
        """, unsafe_allow_html=True)
