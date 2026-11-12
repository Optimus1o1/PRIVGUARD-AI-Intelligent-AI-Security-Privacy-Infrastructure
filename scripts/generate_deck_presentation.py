"""Generates 10-slide PowerPoint (.pptx) and PDF presentations for PRIVGUARD AI.
Startup Buildathon India 2026 Submission.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os
from pathlib import Path
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs" / "buildathon_2026"
SCREENSHOTS_DIR = DOCS_DIR / "screenshots"

PPTX_PATH = DOCS_DIR / "PRIVGUARD_AI_Buildathon_2026.pptx"
PDF_PATH = DOCS_DIR / "PRIVGUARD_AI_Buildathon_2026.pdf"

# Palette: Ink #0F1013, Bone #F2EFE8, Cyan #06B6D4, Emerald #10B981, Amber #F59E0B, Red #EF4444, Slate #8B9099
C_BG = RGBColor(15, 16, 19)        # #0F1013
C_CARD = RGBColor(24, 27, 34)      # Dark Navy Card
C_TEXT = RGBColor(242, 239, 232)   # Bone
C_MUTED = RGBColor(139, 144, 153)  # Slate
C_CYAN = RGBColor(6, 182, 212)     # Cyan
C_EMERALD = RGBColor(16, 185, 129) # Emerald
C_RED = RGBColor(239, 68, 68)      # Red
C_AMBER = RGBColor(245, 158, 11)   # Amber

SLIDES_DATA = [
    {
        "title": "PRIVGUARD AI",
        "subtitle": "The Independent Security Layer for AI Applications",
        "tagline": "Secure every prompt. Govern every tool. Protect every interaction.",
        "bullets": [
            "Decoupling safety and security policy enforcement from probabilistic LLMs.",
            "Local-first privacy enforcement with sensitive-data redaction before model transmission.",
            "Cryptographic task-scoped capability tokens for autonomous agent tools.",
            "Moon Sanctum Labs | Founder: Aniket Nandi (Kolkata, India) | Buildathon 2026"
        ],
        "category": "VISION & POSITIONING",
        "image": None
    },
    {
        "title": "The Problem: The Fallacy of Model Self-Governance",
        "subtitle": "Why Generative AI is Inherently Vulnerable in Production",
        "tagline": "You would never let a web user enforce database permissions. Why trust an LLM to govern itself?",
        "bullets": [
            "Data Ingress Leakage: Customer PII, secrets, and proprietary code sent raw to cloud APIs.",
            "Adversarial Hijacking: Prompt injections and jailbreaks effortlessly override soft system prompts.",
            "Ungoverned Agent Tools: Autonomous agents invoke sensitive APIs without cryptographic boundaries.",
            "Compliance Vacuum: Storing prompts violates DPDP/GDPR; omitting logs blinds forensic investigations."
        ],
        "category": "PROBLEM STATEMENT",
        "image": None
    },
    {
        "title": "The Solution: Deterministic Out-of-Band Gateway",
        "subtitle": "Independent Enforcement Between Applications, Models & Tools",
        "tagline": "Fail-closed security kernel operating independently of model hallucinations.",
        "bullets": [
            "Ingress Defense: Scans secrets (entropy + patterns) & tokenizes PII (<EMAIL_1>, <PHONE_1>).",
            "Adversarial Quarantine: Halts prompt injections with HTTP 403 before model context is loaded.",
            "Tool Authorization: Issues single-use HMAC-SHA256 capability tokens for agent tools.",
            "Content-Free Auditing: Records keyed HMAC-SHA256 fingerprints—zero raw prompt storage."
        ],
        "category": "PROPOSED SOLUTION",
        "image": None
    },
    {
        "title": "Current Product: Five Tested Phase 1 Capabilities",
        "subtitle": "Completed MVP Verified Across 438+ Automated Backend Tests",
        "tagline": "Not a conceptual slide deck—a deployment-qualified security gateway.",
        "bullets": [
            "1. Sensitive Data Protection: Presidio/regex tokenization & safe client-side de-tokenization.",
            "2. Prompt Injection Defense: Deterministic signatures & heuristic quarantine (INJ_OVERRIDE_001).",
            "3. Tool Authorization: Server-side ToolBroker with single-use task-scoped capability tokens.",
            "4. Content-Free Activity Logs: Keyed HMAC fingerprints for DPDP/GDPR compliant forensics.",
            "5. Policy Control Center: User-defined ALLOW/REDACT/BLOCK policies with real-time dry-run."
        ],
        "category": "DELIVERED PRODUCT",
        "image": "playground_desktop_1440x900.png"
    },
    {
        "title": "Live Product: Executive Console & Security Playground",
        "subtitle": "Real-Time Telemetry and Interactive Evaluation Sandbox",
        "tagline": "Full visibility into threats, redactions, and agent capabilities in real time.",
        "bullets": [
            "Interactive Playground: Evaluators test PII redaction, prompt injection, and tool checks.",
            "Executive Telemetry: Real-time counters for requests, blocked threats, and active agents.",
            "Live Local Integration: Tested end-to-end against local Ollama (llama3.2:3b).",
            "Zero Guesswork: Inspect exactly what was redacted and why a threat was quarantined."
        ],
        "category": "PRODUCT SHOWCASE",
        "image": "overview_desktop_1440x900.png"
    },
    {
        "title": "Technical Architecture & Enforcement Boundary",
        "subtitle": "Application -> Ingress Pipeline -> ToolBroker -> Model -> Egress Inspection",
        "tagline": "Zero data egress in local mode; verified sensitive-data redaction in cloud mode.",
        "bullets": [
            "Client Layer: Standard OpenAI-compatible REST proxy interface (/v1/chat/completions).",
            "Ingress Pipeline: Secret scanning, prompt injection defense, PII tokenization.",
            "ToolBroker: Cryptographic HMAC capability validator with strict parameter constraints.",
            "Egress Pipeline: Model leakage inspection, placeholder restoration, content-free logging."
        ],
        "category": "TECHNICAL DESIGN",
        "image": "showcase_desktop_1440x900.png"
    },
    {
        "title": "Market Differentiation: Why PRIVGUARD Wins",
        "subtitle": "Architectural Superiority Over Traditional WAFs and Model Wrappers",
        "tagline": "Deterministic, local-first protection built specifically for the generative AI era.",
        "bullets": [
            "Enforcement Boundary: Operates at the AI application layer, not just generic network packets.",
            "Fail-Closed Philosophy: Malicious inputs and live secrets are blocked before reaching model APIs.",
            "Cryptographic Tool Grants: First gateway to treat agent tools as capability-gated primitives.",
            "Privacy by Design: Never stores raw user prompts, preventing secondary database leaks."
        ],
        "category": "COMPETITIVE ADVANTAGE",
        "image": None
    },
    {
        "title": "Market Opportunity & Business Model Hypotheses",
        "subtitle": "Targeting the $15B+ AI TRiSM (Trust, Risk & Security) Market",
        "tagline": "Developer-first adoption scaling into enterprise compliance infrastructure.",
        "bullets": [
            "Beachhead ICP: AI SaaS startups and engineering teams deploying customer copilots.",
            "Regulatory Urgency: India DPDP Act 2023 (₹250 Cr penalty floor) & EU AI Act compliance.",
            "Community Tier (Free): Local-first gateway, SQLite storage, local Ollama, community rules.",
            "Team & Enterprise ($99 - $5,000/mo): Multi-tenant policies, SIEM export, air-gapped clusters."
        ],
        "category": "MARKET & BUSINESS MODEL",
        "image": None
    },
    {
        "title": "Product Roadmap: The Three-Phase Vision",
        "subtitle": "Clear Engineering Progression from Gateway to Mesh",
        "tagline": "What exists today, and what PRIVGUARD will become.",
        "bullets": [
            "Phase 1: Local-First AI Security Gateway (COMPLETED & QUALIFIED) - 438+ tests passed.",
            "Phase 2: Agent Security & Execution Mesh (PLANNED) - Multi-agent taint tracking & approval hooks.",
            "Phase 3: Privacy Infrastructure (LONG-TERM) - Confidential computing & zero-knowledge proofs.",
            "Commitment: Delivering verified, rock-solid engineering milestones before expanding."
        ],
        "category": "ROADMAP & EXPANSION",
        "image": None
    },
    {
        "title": "Founder & Execution Pedigree: Moon Sanctum Labs",
        "subtitle": "Built from First Principles by Aniket Nandi (Kolkata, India)",
        "tagline": "Decode. Build. Evolve.",
        "bullets": [
            "Solo Founder: Full-stack systems engineer & product designer with obsessive focus on security.",
            "Verified Engineering: Single-handedly built gateway, test suite, and Next.js management console.",
            "Zero Security Vulnerabilities: Passed Bandit (0 high/medium) and Ruff clean static analysis.",
            "Vision: Establishing India's premier homegrown AI security infrastructure platform."
        ],
        "category": "FOUNDER & EXECUTION",
        "image": None
    }
]


def create_pptx():
    prs = Presentation()
    # 16:9 Widescreen
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    for data in SLIDES_DATA:
        slide = prs.slides.add_slide(blank_layout)

        # Background fill
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_BG
        bg.line.color.rgb = C_BG

        # Top Accent Header Bar
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.4))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = f"PRIVGUARD AI  |  {data['category']}"
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = C_CYAN

        # Title
        t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.8), Inches(11.7), Inches(0.9))
        tf_t = t_box.text_frame
        tf_t.word_wrap = True
        p_t = tf_t.paragraphs[0]
        p_t.text = data["title"]
        p_t.font.size = Pt(26)
        p_t.font.bold = True
        p_t.font.color.rgb = C_TEXT

        # Subtitle
        s_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.7), Inches(11.7), Inches(0.5))
        tf_s = s_box.text_frame
        tf_s.word_wrap = True
        p_s = tf_s.paragraphs[0]
        p_s.text = data["subtitle"]
        p_s.font.size = Pt(15)
        p_s.font.color.rgb = C_MUTED

        # Main Content Layout: Split if image exists, else full width cards
        has_image = data["image"] and (SCREENSHOTS_DIR / data["image"]).exists()
        card_width = Inches(5.8) if has_image else Inches(11.7)

        # Content Card Box
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(2.4), card_width, Inches(4.3))
        card.fill.solid()
        card.fill.fore_color.rgb = C_CARD
        card.line.color.rgb = RGBColor(40, 45, 55)

        # Bullets inside card
        tf_card = card.text_frame
        tf_card.word_wrap = True
        tf_card.margin_left = Inches(0.3)
        tf_card.margin_right = Inches(0.3)
        tf_card.margin_top = Inches(0.3)

        # Tagline
        p_tag = tf_card.paragraphs[0]
        p_tag.text = data["tagline"]
        p_tag.font.size = Pt(13)
        p_tag.font.bold = True
        p_tag.font.color.rgb = C_CYAN
        p_tag.space_after = Pt(14)

        for b in data["bullets"]:
            p_b = tf_card.add_paragraph()
            p_b.text = f"•  {b}"
            p_b.font.size = Pt(12)
            p_b.font.color.rgb = C_TEXT
            p_b.space_after = Pt(10)

        # Insert screenshot if present
        if has_image:
            img_path = str(SCREENSHOTS_DIR / data["image"])
            slide.shapes.add_picture(img_path, Inches(6.9), Inches(2.4), width=Inches(5.6))

        # Footer
        f_box = slide.shapes.add_textbox(Inches(0.8), Inches(6.9), Inches(11.7), Inches(0.3))
        tf_f = f_box.text_frame
        p_f = tf_f.paragraphs[0]
        p_f.text = "Moon Sanctum Labs  •  Decode. Build. Evolve.  •  Startup Buildathon India 2026"
        p_f.font.size = Pt(10)
        p_f.font.color.rgb = C_MUTED

    prs.save(str(PPTX_PATH))
    print(f"PowerPoint generated successfully: {PPTX_PATH}")


def create_pdf():
    doc = SimpleDocTemplate(
        str(PDF_PATH),
        pagesize=landscape(letter),
        leftMargin=36,
        rightMargin=36,
        topMargin=28,
        bottomMargin=28,
    )

    styles = getSampleStyleSheet()

    cat_style = ParagraphStyle(
        "CatStyle",
        parent=styles["Normal"],
        fontSize=9,
        leading=11,
        textColor=colors.HexColor("#06B6D4"),
        fontName="Helvetica-Bold",
        textTransform="uppercase",
    )
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Normal"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#F2EFE8"),
        fontName="Helvetica-Bold",
    )
    sub_style = ParagraphStyle(
        "SubStyle",
        parent=styles["Normal"],
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#8B9099"),
        fontName="Helvetica",
    )
    tag_style = ParagraphStyle(
        "TagStyle",
        parent=styles["Normal"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#06B6D4"),
        fontName="Helvetica-Bold",
    )
    bullet_style = ParagraphStyle(
        "BulletStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#F2EFE8"),
        fontName="Helvetica",
    )
    footer_style = ParagraphStyle(
        "FooterStyle",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#8B9099"),
        alignment=1, # Center
    )

    story = []

    for i, data in enumerate(SLIDES_DATA):
        story.append(Paragraph(f"PRIVGUARD AI  |  {data['category']}", cat_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(data["title"], title_style))
        story.append(Spacer(1, 2))
        story.append(Paragraph(data["subtitle"], sub_style))
        story.append(Spacer(1, 14))

        has_image = data["image"] and (SCREENSHOTS_DIR / data["image"]).exists()

        bullet_paras = [Paragraph(f"<b>{data['tagline']}</b>", tag_style), Spacer(1, 8)]
        for b in data["bullets"]:
            bullet_paras.append(Paragraph(f"• {b}", bullet_style))
            bullet_paras.append(Spacer(1, 4))

        if has_image:
            img_path = str(SCREENSHOTS_DIR / data["image"])
            img_obj = Image(img_path, width=320, height=200)
            table_data = [[bullet_paras, img_obj]]
            col_widths = [380, 330]
        else:
            table_data = [[bullet_paras]]
            col_widths = [710]

        card_table = Table(table_data, colWidths=col_widths)
        card_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#181B22")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#282D37")),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(card_table)

        story.append(Spacer(1, 16))
        story.append(Paragraph("Moon Sanctum Labs  •  Decode. Build. Evolve.  •  Startup Buildathon India 2026", footer_style))

        if i < len(SLIDES_DATA) - 1:
            story.append(PageBreak())

    # Draw dark background for each page
    def draw_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#0F1013"))
        canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=True, stroke=False)
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_bg, onLaterPages=draw_bg)
    print(f"PDF generated successfully: {PDF_PATH}")


if __name__ == "__main__":
    create_pptx()
    create_pdf()
