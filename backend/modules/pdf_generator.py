"""
================================================================================
PDF GENERATOR — Forensische PDF-Report-Erstellung via ReportLab
================================================================================
Generiert druckfertige PDF-Berichte aus den Ergebnissen der forensischen
Analyse-Pipeline. Zwei Klassen decken unterschiedliche Berichtstypen ab:

    ForensicPDFGenerator — Standard-Report für einen einzelnen Analyse-Job:
        - Deckblatt mit Aktenzeichen, Analyst und Datum
        - Executive Summary mit Risikobewertung
        - MITRE ATT&CK Taktiken und Techniken (tabellarisch)
        - Top-Anomalien mit Beschreibung und Score
        - IOC-Liste (IPs, Domains, Prozesse, Dateien, Benutzer)
        - Vollständige Event-Timeline (optional, gekürzt auf max. 200 Einträge)

    CasePDFGenerator — Korrelations-Report für einen ganzen Fall (mehrere Jobs):
        - Wie ForensicPDFGenerator, zusätzlich:
        - Quellenübergreifende Korrelationsanalyse (LLM-generiert)
        - Gemeinsame IOCs über alle Quellen hinweg
        - Rekonstruierte Angriffskette aus allen Jobs

Verwendung:
    gen = ForensicPDFGenerator()
    pdf_path = gen.generate(job_data, output_path=Path("data/outputs/job_42/"))

    # Für Fall-Report:
    case_gen = CasePDFGenerator()
    pdf_path  = case_gen.generate(case_data, output_path=Path("data/outputs/case_7/"))

Abhängigkeiten:
    - reportlab (PDF-Rendering — muss installiert sein)
    - re, sys, logging, pathlib, datetime (stdlib)

Kontext: LFX Forensic Analysis System — Export-Schicht (PDF)
================================================================================
"""

import re
import sys
import logging
import importlib.metadata
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
try:
    from reportlab.lib.pdfencrypt import StandardEncryption
    HAS_ENCRYPTION = True
except ImportError:
    HAS_ENCRYPTION = False

logger = logging.getLogger(__name__)

# ── Farben ───────────────────────────────────────────────────────────────────
ACCENT_BLUE = colors.HexColor('#3b82f6')
ACCENT_PURPLE = colors.HexColor('#a855f7')
RISK_CRITICAL = colors.HexColor('#ef4444')
RISK_HIGH = colors.HexColor('#f97316')
RISK_MEDIUM = colors.HexColor('#eab308')
RISK_LOW = colors.HexColor('#3b82f6')
TEXT_PRIMARY = colors.HexColor('#1a1a2e')
TEXT_SECONDARY = colors.HexColor('#4a4a6a')
TABLE_HEADER_BG = colors.HexColor('#1e293b')
TABLE_ROW_ALT = colors.HexColor('#f8fafc')
BORDER_COLOR = colors.HexColor('#e2e8f0')

RISK_COLORS = {
    'critical': RISK_CRITICAL,
    'high': RISK_HIGH,
    'medium': RISK_MEDIUM,
    'low': RISK_LOW,
}

# ── Helle Hintergrundfarben für risikokodierte Tabellenzeilen ─────────────────
# Pastell-Töne: gut lesbar, nicht zu aufdringlich, klare visuelle Hierarchie
RISK_ROW_CRITICAL = colors.HexColor('#fef2f2')   # Sehr hell-rot
RISK_ROW_HIGH     = colors.HexColor('#fff7ed')   # Sehr hell-orange
RISK_ROW_MEDIUM   = colors.HexColor('#fefce8')   # Sehr hell-gelb
RISK_ROW_LOW      = colors.HexColor('#f0fdf4')   # Sehr hell-grün

# ── Sektions-Banner ───────────────────────────────────────────────────────────
SECTION_ACCENT    = colors.HexColor('#3b82f6')   # Blauer Akzentstreifen links
SECTION_BG        = colors.HexColor('#0f172a')   # Sehr dunkles Blau für Banner

# ── Callout-Box Rahmenfarben (dunkler als Hintergrund) ────────────────────────
CALLOUT_BORDER_CRITICAL = colors.HexColor('#fca5a5')
CALLOUT_BORDER_HIGH     = colors.HexColor('#fdba74')
CALLOUT_BORDER_MEDIUM   = colors.HexColor('#fde047')
CALLOUT_BORDER_LOW      = colors.HexColor('#86efac')


def _risk_from_score(score: float) -> str:
    if score >= 0.8: return 'critical'
    if score >= 0.6: return 'high'
    if score >= 0.4: return 'medium'
    return 'low'


class ForensicPDFGenerator:
    """Generiert forensische PDF-Reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.page_width, self.page_height = A4

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CoverTitle', fontSize=26, leading=32,
            textColor=TEXT_PRIMARY, alignment=TA_CENTER,
            spaceAfter=10, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CoverSubtitle', fontSize=12, leading=16,
            textColor=TEXT_SECONDARY, alignment=TA_CENTER, spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle', fontSize=14, leading=18,
            textColor=TEXT_PRIMARY, spaceBefore=16, spaceAfter=8,
            fontName='Helvetica-Bold', keepWithNext=1,
        ))
        self.styles.add(ParagraphStyle(
            name='SubSection', fontSize=11, leading=14,
            textColor=TEXT_PRIMARY, spaceBefore=10, spaceAfter=5,
            fontName='Helvetica-Bold', keepWithNext=1,
        ))
        self.styles.add(ParagraphStyle(
            name='Body', fontSize=9, leading=13,
            textColor=TEXT_SECONDARY, spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name='Small', fontSize=8, leading=10,
            textColor=TEXT_SECONDARY,
        ))
        self.styles.add(ParagraphStyle(
            name='Footer', fontSize=7, leading=9,
            textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER,
        ))
        # Tabellenzellen-Styles (fuer automatischen Zeilenumbruch)
        self.styles.add(ParagraphStyle(
            name='CellDefault', fontSize=7, leading=9,
            textColor=TEXT_SECONDARY,
        ))
        self.styles.add(ParagraphStyle(
            name='CellHeader', fontSize=7, leading=9,
            textColor=colors.white, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CellPurple', fontSize=7, leading=9,
            textColor=ACCENT_PURPLE,
        ))
        # ── Sektions-Banner ────────────────────────────────────────────────
        self.styles.add(ParagraphStyle(
            name='SectionBanner', fontSize=11, leading=14,
            textColor=colors.white, fontName='Helvetica-Bold',
            spaceBefore=12, spaceAfter=6, leftIndent=6,
        ))
        # ── Risk-Level-Banner (großes zentriertes Risiko-Label) ────────────
        self.styles.add(ParagraphStyle(
            name='RiskBanner', fontSize=20, leading=24,
            textColor=colors.white, fontName='Helvetica-Bold',
            alignment=TA_CENTER, spaceAfter=4,
        ))
        # ── Callout-Box Titel ─────────────────────────────────────────────
        self.styles.add(ParagraphStyle(
            name='AlertTitle', fontSize=8, leading=10,
            textColor=TEXT_PRIMARY, fontName='Helvetica-Bold', spaceAfter=2,
        ))
        # ── Callout-Box Body ──────────────────────────────────────────────
        self.styles.add(ParagraphStyle(
            name='AlertBody', fontSize=8, leading=11,
            textColor=TEXT_SECONDARY,
        ))

    def generate(self, output_path: Path, job_data: Dict) -> Path:
        """Generiert den vollstaendigen PDF-Report."""
        pdf_path = output_path / 'forensic_report.pdf'

        kwargs = dict(
            pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=25*mm, bottomMargin=20*mm,
        )
        # Schreibschutz: Lesen + Drucken erlaubt, Aendern verboten
        if HAS_ENCRYPTION:
            kwargs['encrypt'] = StandardEncryption(
                userPassword='',
                ownerPassword='lfw-forensic-readonly',
                canModify=0,
                canPrint=1,
                canCopy=1,
            )

        doc = SimpleDocTemplate(str(pdf_path), **kwargs)

        story = []
        story.extend(self._build_cover(job_data))
        story.append(PageBreak())
        story.extend(self._build_auftrag_sektion(job_data))
        story.extend(self._build_chain_of_custody(job_data))
        story.extend(self._build_executive_summary(job_data))
        story.extend(self._build_anomalies_table(job_data))
        story.extend(self._build_provenance_table(job_data))
        story.extend(self._build_mitre_summary(job_data))
        story.extend(self._build_ioc_list(job_data))
        story.extend(self._build_methodology())
        story.extend(self._build_limitationen())
        story.append(PageBreak())
        story.extend(self._build_sachverstaendigen_erklaerung(job_data))

        doc.build(story, onFirstPage=self._page_header_footer, onLaterPages=self._page_header_footer)
        logger.info(f"PDF-Report generiert: {pdf_path}")
        return pdf_path

    def _page_header_footer(self, canvas, doc):
        """Header und Footer auf jeder Seite."""
        canvas.saveState()
        # Header
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.drawString(20*mm, self.page_height - 15*mm, 'LFX Forensic Analysis System')
        canvas.drawRightString(self.page_width - 20*mm, self.page_height - 15*mm, 'VERTRAULICH')
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.line(20*mm, self.page_height - 17*mm, self.page_width - 20*mm, self.page_height - 17*mm)
        # Footer
        canvas.drawCentredString(self.page_width / 2, 12*mm, f'Seite {doc.page}')
        canvas.drawRightString(self.page_width - 20*mm, 12*mm, datetime.now().strftime('%d.%m.%Y'))
        canvas.restoreState()

    # ── Visuelle Helper-Methoden ─────────────────────────────────────────────

    def _section_banner(self, text: str, color=None) -> Table:
        """
        Farbiges Sektions-Banner mit weißem Text auf dunklem Hintergrund.
        Ersetzt einfache SectionTitle-Überschriften für bessere visuelle Hierarchie.

        Args:
            text:  Sektionsbezeichnung (z. B. '3. Executive Summary')
            color: Hintergrundfarbe (Standard: SECTION_BG dunkelblau)
        """
        bg = color or SECTION_BG
        p = Paragraph(text, self.styles['SectionBanner'])
        t = Table([[p]], colWidths=[170*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return t

    def _callout_box(self, title: str, body: str, risk: str) -> Table:
        """
        Farbige Callout-Box für Top-Findings im Executive Summary.
        Farbiger linker Balken signalisiert Risiko-Schweregrad.

        Args:
            title: Kurzbezeichnung des Findings (z. B. '1. Kritischer Befund')
            body:  Beschreibungstext (max. ~100 Zeichen)
            risk:  'critical' | 'high' | 'medium' | 'low'
        """
        border_color_map = {
            'critical': CALLOUT_BORDER_CRITICAL,
            'high':     CALLOUT_BORDER_HIGH,
            'medium':   CALLOUT_BORDER_MEDIUM,
            'low':      CALLOUT_BORDER_LOW,
        }
        bg_color_map = {
            'critical': RISK_ROW_CRITICAL,
            'high':     RISK_ROW_HIGH,
            'medium':   RISK_ROW_MEDIUM,
            'low':      RISK_ROW_LOW,
        }
        bc = border_color_map.get(risk, CALLOUT_BORDER_LOW)
        bg = bg_color_map.get(risk, colors.white)

        # Zweispaltig: 5mm Farbstreifen links, 165mm Inhalt rechts (gesamt 170mm)
        # Padding: links 6mm, rechts 4mm → Inhalt-Breite = 165 - 6 - 4 = 155mm
        title_p = Paragraph(title, self.styles['AlertTitle'])
        body_p  = Paragraph(body,  self.styles['AlertBody'])
        inner = Table(
            [[title_p], [body_p]],
            colWidths=[155*mm],
        )
        inner.setStyle(TableStyle([
            ('TOPPADDING',    (0, 0), (-1, -1), 1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
        ]))
        t = Table([[Paragraph(' ', self.styles['Small']), inner]], colWidths=[5*mm, 165*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (0, -1), bc),
            ('BACKGROUND',    (1, 0), (1, -1), bg),
            ('BOX',           (0, 0), (-1, -1), 0.5, bc),
            ('TOPPADDING',    (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING',   (1, 0), (1, -1), 6),
            ('RIGHTPADDING',  (1, 0), (1, -1), 4),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        return t

    def _score_bar(self, score: float, risk: str) -> str:
        """
        Gibt einen Unicode-Balken zurück der den Anomalie-Score visualisiert.
        Wird als Text in einer Tabellenzelle verwendet.

        Args:
            score: float 0.0–1.0
            risk:  'critical' | 'high' | 'medium' | 'low'
        """
        score = score or 0.0
        filled = round(score * 10)
        bar = '|' * filled + '.' * (10 - filled)
        pct = f"{score:.0%}"
        return f'<font face="Courier" size="6">{bar}</font> {pct}'

    def _build_cover(self, data: Dict) -> list:
        """Deckblatt."""
        story = []
        story.append(Spacer(1, 30*mm))
        story.append(Paragraph('FORENSISCHER<br/>ANALYSEBERICHT', self.styles['CoverTitle']))
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph('LFX Forensic Analysis System', self.styles['CoverSubtitle']))
        story.append(Spacer(1, 20*mm))

        # Metadaten-Tabelle
        summary = data.get('summary', {})
        meta_rows = [
            ['Datum', datetime.now().strftime('%d.%m.%Y %H:%M')],
            ['Eingabedatei', data.get('filename', 'Unbekannt')],
            ['Dateityp', data.get('input_type', 'Unbekannt')],
            ['Events analysiert', str(summary.get('total_events', '—'))],
            ['Anomalien erkannt', str(summary.get('anomalies_found', '—'))],
            ['IOCs identifiziert', str(summary.get('iocs_identified', '—'))],
        ]

        # MD5 + SHA256 wenn vorhanden
        if data.get('md5_hash'):
            meta_rows.append(['MD5', data['md5_hash']])
        if data.get('sha256_hash') or data.get('file_hash'):
            meta_rows.append(['SHA256', data.get('sha256_hash') or data.get('file_hash')])

        # Case-Info wenn vorhanden
        if data.get('case_name'):
            meta_rows.insert(0, ['Fall', data['case_name']])
        if data.get('case_number'):
            meta_rows.insert(1, ['Aktenzeichen', data['case_number']])
        if data.get('auftraggeber'):
            meta_rows.append(['Auftraggeber', data['auftraggeber']])
        if data.get('analyst'):
            meta_rows.append(['Gutachter', data['analyst']])
        if data.get('qualifikation'):
            meta_rows.append(['Qualifikation', data['qualifikation']])
        meta_rows.append(['Signatur', 'In Produktivumgebung: qual. elektron. Signatur nach eIDAS'])

        t = Table(meta_rows, colWidths=[45*mm, 80*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_SECONDARY),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)

        story.append(Spacer(1, 30*mm))
        story.append(Paragraph(
            'Vertraulich — Nur fuer autorisierten Gebrauch',
            self.styles['Footer']
        ))
        return story

    def _build_executive_summary(self, data: Dict) -> list:
        """Executive Summary mit Risk-Banner und Callout-Boxen."""
        story = []
        story.append(self._section_banner('3. Executive Summary'))
        story.append(Spacer(1, 3*mm))

        summary = data.get('summary', {})
        anomalies = data.get('anomalies', [])

        # Gesamtrisiko berechnen
        if anomalies:
            max_score = max(a.get('anomaly_score', 0) for a in anomalies)
            risk_level = _risk_from_score(max_score)
        else:
            max_score = 0
            risk_level = 'low'

        risk_text = {'critical': 'KRITISCH', 'high': 'HOCH', 'medium': 'MITTEL', 'low': 'NIEDRIG'}
        risk_color = RISK_COLORS.get(risk_level, RISK_LOW)

        # ── Großes Risk-Level-Banner ───────────────────────────────────────
        risk_label = risk_text.get(risk_level, 'UNBEKANNT')
        risk_p = Paragraph(f'GESAMTRISIKO: {risk_label}', self.styles['RiskBanner'])
        risk_banner = Table([[risk_p]], colWidths=[170*mm])
        risk_banner.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), risk_color),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(risk_banner)
        story.append(Spacer(1, 4*mm))

        # ── Metriken-Tabelle ──────────────────────────────────────────────
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        metric_header = [
            Paragraph('Total Events', cell_h),
            Paragraph('Anomalien', cell_h),
            Paragraph('IOCs', cell_h),
            Paragraph('Max. Score', cell_h),
        ]
        metric_values = [
            Paragraph(f"<b>{summary.get('total_events', 0)}</b>", self.styles['SubSection']),
            Paragraph(f"<b>{summary.get('anomalies_found', len(anomalies))}</b>", self.styles['SubSection']),
            Paragraph(f"<b>{summary.get('iocs_identified', 0)}</b>", self.styles['SubSection']),
            Paragraph(f"<b>{max_score:.0%}</b>", self.styles['SubSection']),
        ]
        metrics_t = Table([metric_header, metric_values], colWidths=[42*mm, 42*mm, 42*mm, 42*mm])
        metrics_t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BACKGROUND', (0, 1), (-1, 1), TABLE_ROW_ALT),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(metrics_t)
        story.append(Spacer(1, 5*mm))

        # ── Top-3 Callout-Boxen ───────────────────────────────────────────
        if anomalies:
            story.append(Paragraph('Top-3 Kritische Befunde:', self.styles['SubSection']))
            story.append(Spacer(1, 2*mm))
            top3 = sorted(anomalies, key=lambda a: a.get('anomaly_score', 0), reverse=True)[:3]
            for i, a in enumerate(top3, 1):
                score = a.get('anomaly_score', 0)
                rlvl = _risk_from_score(score)
                desc = (a.get('description', a.get('event', '')) or '')[:110]
                mitre_tags = ', '.join(tk['id'] for tk in a.get('mitre_techniques', [])[:2])
                title_line = f"{i}. [{score:.0%}] {a.get('event_type', '—')}"
                if mitre_tags:
                    title_line += f'  ({mitre_tags})'
                story.append(self._callout_box(title_line, desc, rlvl))
                story.append(Spacer(1, 2*mm))

        story.append(Spacer(1, 4*mm))
        return story

    def _build_anomalies_table(self, data: Dict) -> list:
        """Anomalien-Tabelle mit Risiko-Farbkodierung und Score-Balken."""
        story = []
        anomalies = data.get('anomalies', [])
        if not anomalies:
            return story

        story.append(self._section_banner('4. Erkannte Anomalien'))
        story.append(Spacer(1, 3*mm))

        # Legende
        legend_items = [
            [
                Paragraph('', self.styles['Small']),
                Paragraph('<b>■</b> KRITISCH (≥80%)', self.styles['Small']),
                Paragraph('<b>■</b> HOCH (≥60%)', self.styles['Small']),
                Paragraph('<b>■</b> MITTEL (≥40%)', self.styles['Small']),
                Paragraph('<b>■</b> NIEDRIG (<40%)', self.styles['Small']),
            ]
        ]
        legend_t = Table(legend_items, colWidths=[10*mm, 35*mm, 35*mm, 35*mm, 35*mm])
        legend_t.setStyle(TableStyle([
            ('TEXTCOLOR', (1, 0), (1, 0), RISK_CRITICAL),
            ('TEXTCOLOR', (2, 0), (2, 0), RISK_HIGH),
            ('TEXTCOLOR', (3, 0), (3, 0), RISK_MEDIUM),
            ('TEXTCOLOR', (4, 0), (4, 0), RISK_LOW),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ]))
        story.append(legend_t)
        story.append(Spacer(1, 2*mm))

        # Header mit Paragraph fuer konsistentes Rendering
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_p = self.styles['CellPurple']

        header = [
            Paragraph('Nr', cell_h),
            Paragraph('Zeitstempel', cell_h),
            Paragraph('Typ', cell_h),
            Paragraph('Score / Balken', cell_h),
            Paragraph('MITRE', cell_h),
            Paragraph('Beschreibung', cell_h),
        ]
        rows = [header]
        # Risikolevel pro Datenzeile merken (Index = Zeilennummer im Table)
        row_risks = []

        sorted_anomalies = sorted(anomalies, key=lambda a: a.get('anomaly_score', 0), reverse=True)
        for i, a in enumerate(sorted_anomalies[:30], 1):
            ts = a.get('timestamp', '—')[:19]
            etype = a.get('event_type', '—')[:20]
            score_val = a.get('anomaly_score', 0)
            rlvl = _risk_from_score(score_val)
            score_str = self._score_bar(score_val, rlvl)
            mitre = ', '.join(tk['id'] for tk in a.get('mitre_techniques', [])[:2])
            desc = (a.get('description', '') or '')[:120]
            rows.append([
                Paragraph(str(i), cell_d),
                Paragraph(ts, cell_d),
                Paragraph(etype, cell_d),
                Paragraph(score_str, cell_d),
                Paragraph(mitre, cell_p),
                Paragraph(desc, cell_d),
            ])
            row_risks.append(rlvl)

        col_widths = [10*mm, 30*mm, 25*mm, 28*mm, 25*mm, 42*mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)

        # Risiko-Farbkodierung: jede Datenzeile bekommt ihre Hintergrundfarbe
        row_bg_map = {
            'critical': RISK_ROW_CRITICAL,
            'high':     RISK_ROW_HIGH,
            'medium':   RISK_ROW_MEDIUM,
            'low':      RISK_ROW_LOW,
        }
        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        for row_idx, rlvl in enumerate(row_risks, 1):
            bg = row_bg_map.get(rlvl, colors.white)
            style_commands.append(('BACKGROUND', (0, row_idx), (-1, row_idx), bg))

        t.setStyle(TableStyle(style_commands))
        story.append(t)

        if len(anomalies) > 30:
            story.append(Paragraph(
                f'<i>({len(anomalies) - 30} weitere Anomalien nicht angezeigt)</i>',
                self.styles['Small']
            ))
        story.append(Spacer(1, 5*mm))
        return story

    def _build_mitre_summary(self, data: Dict) -> list:
        """MITRE ATT&CK Uebersicht."""
        story = []
        anomalies = data.get('anomalies', [])

        # Techniken sammeln
        technique_map: Dict[str, Dict] = {}
        for a in anomalies:
            for t in a.get('mitre_techniques', []):
                tid = t['id']
                if tid not in technique_map:
                    technique_map[tid] = {'id': tid, 'name': t['name'], 'tactic': t['tactic'], 'count': 0}
                technique_map[tid]['count'] += 1

        if not technique_map:
            return story

        story.append(self._section_banner('5. MITRE ATT&CK Zuordnung'))

        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_p = self.styles['CellPurple']

        header = [
            Paragraph('Technik-ID', cell_h),
            Paragraph('Name', cell_h),
            Paragraph('Taktik', cell_h),
            Paragraph('Anzahl', cell_h),
        ]
        rows = [header]
        for tech in sorted(technique_map.values(), key=lambda x: x['count'], reverse=True):
            rows.append([
                Paragraph(tech['id'], cell_p),
                Paragraph(tech['name'], cell_d),
                Paragraph(tech['tactic'], cell_d),
                Paragraph(str(tech['count']), cell_d),
            ])

        t = Table(rows, colWidths=[25*mm, 55*mm, 45*mm, 18*mm], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))
        return story

    def _build_ioc_list(self, data: Dict) -> list:
        """IOC-Liste."""
        story = []
        indicators = data.get('indicators', {})

        # Pruefen ob IOCs vorhanden
        has_iocs = any(indicators.get(k) for k in ['ips', 'domains', 'users', 'hostnames', 'processes', 'files'])
        if not has_iocs:
            return story

        story.append(self._section_banner('6. Indicators of Compromise (IOCs)'))

        ioc_sections = [
            ('ips', 'IP-Adressen'),
            ('domains', 'Domains'),
            ('users', 'Benutzerkonten'),
            ('hostnames', 'Hostnamen'),
            ('processes', 'Prozesse'),
            ('files', 'Verdaechtige Dateien'),
        ]

        for key, label in ioc_sections:
            vals = indicators.get(key, [])
            if not vals:
                continue
            story.append(Paragraph(f'{label}:', self.styles['SubSection']))
            for v in vals[:20]:
                story.append(Paragraph(f'&bull;  <font face="Courier" size="8">{str(v)[:80]}</font>', self.styles['Body']))

        story.append(Spacer(1, 5*mm))
        return story

    def _build_methodology(self) -> list:
        """Methodologie-Abschnitt."""
        story = []
        story.append(self._section_banner('7. Methodologie'))
        story.append(Paragraph(
            'Dieser Report wurde automatisch durch das LFX Forensic Analysis System generiert. '
            'Die Analyse umfasst folgende Komponenten:', self.styles['Body']
        ))
        methods = [
            '<b>Log-Parsing:</b> Automatische Erkennung und Parsing von Syslog, Apache, Windows Event, '
            'Firewall und Pipe-delimited Log-Formaten.',
            '<b>ML-Anomalieerkennung:</b> Isolation Forest Algorithmus (scikit-learn) mit 8 Features '
            'inklusive Event-Typ-Score, Zeitanalyse, Keyword-Erkennung und IP-Analyse.',
            '<b>MITRE ATT&CK Mapping:</b> Automatische Zuordnung erkannter Event-Typen zu MITRE ATT&CK '
            'Enterprise v14 Techniken und Taktiken.',
            '<b>IOC-Extraktion:</b> Automatische Erkennung von IP-Adressen, Domains, Benutzerkonten '
            'und verdächtigen Dateipfaden aus den analysierten Events.',
        ]
        for m in methods:
            story.append(Paragraph(f'&bull;  {m}', self.styles['Body']))

        # ML-Hyperparameter (fuer Reproduzierbarkeit und gerichtliche Verwertbarkeit)
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph('7.1 IsolationForest — Hyperparameter', self.styles['SubSection']))
        story.append(Paragraph(
            'Alle Parameter sind fest kodiert und garantieren vollständige Reproduzierbarkeit '
            'der Ergebnisse (ENFSI Best Practice Manual 2015):', self.styles['Body']
        ))
        ml_params = [
            ['Parameter', 'Wert', 'Beschreibung'],
            ['n_estimators', '100', 'Anzahl der Entscheidungsbäume im Wald'],
            ['contamination', '0.1', 'Erwarteter Anomalieanteil: 10 % der Events'],
            ['random_state', '42', 'Fixer Seed — Ergebnisse sind 100 % reproduzierbar'],
            ['Features (8)', 'hour, day_of_week, event_type_score, is_off_hours,',
             'suspicious_keyword_count, has_external_ip, message_length, file_size_log'],
        ]
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        rows = []
        for i, row in enumerate(ml_params):
            style = cell_h if i == 0 else cell_d
            rows.append([Paragraph(str(c), style) for c in row])
        t = Table(rows, colWidths=[35*mm, 25*mm, 100*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Paragraph(
            '<i>Hinweis: Ergebnisse sind probabilistisch. IsolationForest dient als '
            'Hypothesengenerierung, nicht als rechtlicher Beweis (vgl. Abschnitt 8).</i>',
            self.styles['Small']
        ))

        # Tool-Versionen (dynamisch ermittelt)
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph('7.2 Verwendete Software und Versionen', self.styles['SubSection']))

        def _get_version(pkg: str) -> str:
            try:
                return importlib.metadata.version(pkg)
            except Exception:
                return 'nicht ermittelbar'

        version_rows = [
            [Paragraph('Software', cell_h), Paragraph('Version', cell_h)],
            [Paragraph('Python', cell_d), Paragraph(sys.version.split()[0], cell_d)],
            [Paragraph('scikit-learn', cell_d), Paragraph(_get_version('scikit-learn'), cell_d)],
            [Paragraph('reportlab', cell_d), Paragraph(_get_version('reportlab'), cell_d)],
            [Paragraph('dissect.target', cell_d), Paragraph(_get_version('dissect.target'), cell_d)],
            [Paragraph('pytsk3 (Sleuth Kit)', cell_d), Paragraph(_get_version('pytsk3'), cell_d)],
            [Paragraph('python-magic', cell_d), Paragraph(_get_version('python-magic'), cell_d)],
            [Paragraph('LFX Forensic Analysis System', cell_d), Paragraph('v1.1', cell_d)],
        ]
        tv = Table(version_rows, colWidths=[80*mm, 80*mm])
        tv.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(tv)

        story.append(Spacer(1, 8*mm))
        story.append(HRFlowable(width='100%', color=BORDER_COLOR))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            'LFX Forensic Analysis System v1.1 — Generiert am ' + datetime.now().strftime('%d.%m.%Y um %H:%M Uhr'),
            self.styles['Footer']
        ))
        return story

    def _build_auftrag_sektion(self, data: Dict) -> list:
        """Auftrag und Untersuchungsumfang (gerichtliche Pflichtsektion)."""
        story = []
        story.append(self._section_banner('1. Auftrag und Untersuchungsumfang'))

        rows = [
            ['Auftraggeber', data.get('auftraggeber', 'Nicht angegeben')],
            ['Untersuchungsgegenstand', data.get('filename', 'Unbekannt')],
            ['Eingabetyp', data.get('input_type', 'Unbekannt')],
            ['SHA-256 (Beweismittel)', data.get('sha256_hash') or data.get('file_hash', 'Nicht berechnet')],
            ['Analysezeitpunkt', data.get('created_at', datetime.now().strftime('%d.%m.%Y %H:%M'))],
        ]
        t = Table(rows, colWidths=[50*mm, 110*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_SECONDARY),
            ('BACKGROUND', (0, 0), (-1, -1), TABLE_ROW_ALT),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        story.append(Spacer(1, 4*mm))

        story.append(Paragraph('Untersuchungsumfang:', self.styles['SubSection']))
        scope_items = [
            'Vollständige Analyse des Dateisystems und vorhandener Log-Dateien',
            'ML-basierte Anomalieerkennung (IsolationForest)',
            'MITRE ATT&CK Mapping erkannter Ereignisse',
            'Extraktion von Indicators of Compromise (IOCs)',
        ]
        for item in scope_items:
            story.append(Paragraph(f'&bull;  {item}', self.styles['Body']))

        story.append(Paragraph('Nicht Gegenstand dieser Untersuchung:', self.styles['SubSection']))
        excluded_items = [
            'Memory-Forensik (flüchtige Speicheranalyse / RAM)',
            'Live-Netzwerkverkehr (Netzwerk-Captures)',
            'Externe Systeme und vernetzte Geräte',
            'Verschlüsselte Dateibereiche (ohne Schlüssel)',
        ]
        for item in excluded_items:
            story.append(Paragraph(f'&bull;  {item}', self.styles['Body']))

        story.append(Spacer(1, 5*mm))
        return story

    def _build_chain_of_custody(self, data: Dict) -> list:
        """Chain of Custody — Beweismittelkette (ISO/IEC 27037 Pflicht)."""
        story = []
        story.append(self._section_banner('2. Chain of Custody — Beweismittelkette'))
        story.append(Paragraph(
            'Gemäß ISO/IEC 27037:2012 und BSI Leitfaden IT-Forensik wird die lückenlose '
            'Dokumentation der Beweismittelkette sichergestellt:', self.styles['Body']
        ))
        story.append(Spacer(1, 3*mm))

        rows = [
            ['Beweismittel-ID (Job-ID)', data.get('job_id', 'Nicht angegeben')],
            ['Dateiname', data.get('filename', 'Unbekannt')],
            ['MD5-Hash', data.get('md5_hash', 'Nicht berechnet')],
            ['SHA-256-Hash', data.get('sha256_hash') or data.get('file_hash', 'Nicht berechnet')],
            ['Zeitpunkt der Analyse', data.get('created_at', datetime.now().strftime('%d.%m.%Y %H:%M'))],
            ['Analysierender', data.get('analyst', 'Nicht angegeben')],
            ['Analysemethode', data.get('input_type', 'Automatische Erkennung')],
            ['Zugriffsart', 'Ausschließlich lesender Zugriff (kein Schreiben auf Beweismittel)'],
            ['Write-Blocker-Hinweis', 'In Produktivumgebung: Hardware-Write-Blocker erforderlich (z. B. Tableau T35u)'],
        ]
        t = Table(rows, colWidths=[60*mm, 100*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_SECONDARY),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [TABLE_ROW_ALT, colors.white]),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))
        return story

    def _build_provenance_table(self, data: Dict) -> list:
        """
        Fundstellen-Nachweis-Tabelle (ISO/IEC 27037 — Reproduzierbarkeit).

        Zeigt für jede Anomalie exakt, in welchem Asservat, welcher Datei und
        an welcher Stelle (Inode / Zeilennummer) der Befund gefunden wurde.
        Damit kann jeder Gutachter oder Verteidiger jeden Befund 1:1 nachstellen.

        Wird nur gerendert wenn 'provenance' in job_data vorhanden und nicht leer.
        """
        provenance = data.get('provenance', [])
        if not provenance:
            return []

        story = []
        story.append(self._section_banner('4a. Fundstellen-Nachweis (Provenance)'))
        story.append(Paragraph(
            'Gemäß ISO/IEC 27037:2012 wird für jede erkannte Anomalie die exakte Fundstelle '
            'im Asservat dokumentiert. Die Angaben ermöglichen die vollständige Reproduzierbarkeit '
            'durch einen unabhängigen Gutachter.',
            self.styles['Body']
        ))
        story.append(Spacer(1, 3*mm))

        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_p = self.styles['CellPurple']

        header = [
            Paragraph('Nr', cell_h),
            Paragraph('Asservat', cell_h),
            Paragraph('Datei / Pfad', cell_h),
            Paragraph('Fundstelle', cell_h),
            Paragraph('Extrahiert mit', cell_h),
            Paragraph('Score', cell_h),
        ]
        rows = [header]

        for entry in provenance[:40]:  # max. 40 Einträge für Lesbarkeit
            nr          = str(entry.get('nr', ''))
            evidence    = str(entry.get('evidence_file', '—'))[:30]
            found_in    = str(entry.get('found_in_file', '—'))[:35]
            location    = str(entry.get('location_detail', '—'))[:35]
            tool        = str(entry.get('extracted_by', '—'))[:25]
            score_val   = entry.get('anomaly_score', 0)
            score       = f"{score_val:.0%}" if isinstance(score_val, float) else str(score_val)

            rows.append([
                Paragraph(nr, cell_d),
                Paragraph(evidence, cell_d),
                Paragraph(found_in, cell_d),
                Paragraph(location, cell_d),
                Paragraph(tool, cell_p),
                Paragraph(score, cell_d),
            ])

        col_widths = [8*mm, 32*mm, 40*mm, 38*mm, 30*mm, 12*mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)

        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style_commands.append(('BACKGROUND', (0, i), (-1, i), TABLE_ROW_ALT))

        t.setStyle(TableStyle(style_commands))
        story.append(t)

        if len(provenance) > 40:
            story.append(Paragraph(
                f'<i>({len(provenance) - 40} weitere Fundstellen in provenance.json)</i>',
                self.styles['Small']
            ))
        story.append(Spacer(1, 5*mm))
        return story

    def _build_limitationen(self) -> list:
        """Limitationen und Unsicherheiten (ENFSI-Pflichtabschnitt)."""
        story = []
        story.append(self._section_banner('8. Limitationen und Unsicherheiten'))
        story.append(Paragraph(
            'Gemäß ENFSI Best Practice Manual (2015) und ISO/IEC 27037:2012 müssen alle '
            'bekannten Einschränkungen und Unsicherheiten deklariert werden:', self.styles['Body']
        ))
        story.append(Spacer(1, 3*mm))

        limitations = [
            (
                'ML-Unsicherheit (IsolationForest)',
                'Der verwendete Algorithmus erzeugt probabilistische Ergebnisse. Die eingestellte '
                'Kontaminationsrate von 10 % (contamination=0.1) bedeutet, dass ca. 10 % der als '
                'anomal markierten Events False Positives sein können. Alle Anomalie-Befunde '
                'müssen durch einen Fachmann manuell verifiziert werden.'
            ),
            (
                'Zeitstempel-Integrität',
                'Zeitstempel können durch Anti-Forensik-Techniken (Time-Stomping, Timestomping) '
                'manipuliert worden sein. Die Authentizität der Zeitstempel kann ohne '
                'unabhängige Referenzquelle nicht garantiert werden.'
            ),
            (
                'Verschlüsselte Bereiche',
                'Verschlüsselte Dateien, Partitionen oder Container wurden nicht analysiert '
                'und sind in diesem Report nicht enthalten. Entsprechende Bereiche können '
                'forensisch relevante Daten enthalten.'
            ),
            (
                'KI-generierte Inhalte',
                'LLM-basierte Analyseinhalte (sofern vorhanden) sind KI-generiert und können '
                'Fehler enthalten. Sie ersetzen keine manuelle Analyse durch einen qualifizierten '
                'IT-Forensiker und sind als Hypothesen zu betrachten.'
            ),
            (
                'Untersuchungsumfang',
                'Die Analyse beschränkt sich auf die übergebene Eingabedatei. Externe Systeme, '
                'Netzwerkverkehr, flüchtige Speicherinhalte (RAM) und nicht zugängliche '
                'Dateisystembereiche wurden nicht untersucht.'
            ),
        ]

        for i, (title, text) in enumerate(limitations, 1):
            story.append(Paragraph(f'<b>{i}. {title}</b>', self.styles['Body']))
            story.append(Paragraph(text, self.styles['Body']))
            story.append(Spacer(1, 2*mm))

        story.append(Spacer(1, 5*mm))
        return story

    # ── Vollständiger Report: Neue Methoden ──────────────────────────────────

    def _agent_info_box(self, agent_label: str, agent_desc: str, ts: str = '') -> Table:
        """
        Farbige Info-Box die den KI-Agenten und seine Rolle kennzeichnet.
        Erscheint oben in jeder KI-Analyse-Sektion.
        """
        lines = [Paragraph(f'<b>{agent_label}</b>', self.styles['AlertTitle'])]
        lines.append(Paragraph(agent_desc, self.styles['AlertBody']))
        if ts:
            lines.append(Paragraph(
                f'Analyse-Zeitpunkt: {ts} UTC',
                self.styles['Small']
            ))
        lines.append(Paragraph(
            '<i>Hinweis: KI-generierte Inhalte — Ergebnisse als Hypothesen betrachten '
            '(vgl. Abschnitt 8).</i>',
            self.styles['Small']
        ))
        inner = Table([[p] for p in lines], colWidths=[151*mm])
        inner.setStyle(TableStyle([
            ('TOPPADDING',    (0, 0), (-1, -1), 1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
        ]))
        t = Table([[Paragraph(' ', self.styles['Small']), inner]], colWidths=[5*mm, 165*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (0, -1), ACCENT_BLUE),
            ('BACKGROUND',    (1, 0), (1, -1), colors.HexColor('#eff6ff')),
            ('BOX',           (0, 0), (-1, -1), 0.5, ACCENT_BLUE),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING',   (1, 0), (1, -1), 8),
            ('RIGHTPADDING',  (1, 0), (1, -1), 6),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ]))
        return t

    def _md_subsection_banner(self, text: str) -> Table:
        """
        Leichtes Banner für ### Überschriften im Markdown-Text.
        Heller als _section_banner, aber deutlicher als SubSection-Paragraph.
        """
        p = Paragraph(text, self.styles['SubSection'])
        t = Table([[p]], colWidths=[170*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#1e3a5f')),
            ('TOPPADDING',    (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
        ]))
        # SubSection-Style hat textColor=TEXT_PRIMARY (dunkel) — überschreiben
        p.style = ParagraphStyle(
            'SubSectionWhite', parent=self.styles['SubSection'],
            textColor=colors.white, spaceBefore=0, spaceAfter=0,
        )
        return t

    def _md_bullet_block(self, items: list) -> Table:
        """
        Rendert eine Gruppe von Bullet-Punkten als eingerückte Tabelle
        mit hellgrauem Hintergrund — besser lesbar als einfache Paragraphen.
        """
        rows = [[Paragraph(f'&bull;', self.styles['Body']),
                 Paragraph(item, self.styles['Body'])] for item in items]
        t = Table(rows, colWidths=[6*mm, 158*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('LEFTPADDING',   (0, 0), (0, -1),  4),
            ('RIGHTPADDING',  (0, 0), (0, -1),  0),
            ('LEFTPADDING',   (1, 0), (1, -1),  4),
            ('RIGHTPADDING',  (1, 0), (1, -1),  6),
            ('TOPPADDING',    (0, 0), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('BOX',           (0, 0), (-1, -1), 0.3, BORDER_COLOR),
            ('LINEAFTER',     (0, 0), (0, -1),  0.3, BORDER_COLOR),
        ]))
        return t

    def _md_table(self, header_cells: list, data_rows: list) -> Table:
        """
        Rendert eine Markdown-Tabelle als echte ReportLab-Tabelle.
        """
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        n = len(header_cells) or 1
        col_w = 160 / n
        rows = [[Paragraph(c, cell_h) for c in header_cells]]
        for dr in data_rows:
            rows.append([Paragraph(c, cell_d) for c in dr])
        t = Table(rows, colWidths=[col_w*mm]*n, repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0),  TABLE_HEADER_BG),
            ('BOX',           (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID',     (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING',    (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS',(0, 1), (-1, -1), [colors.white, TABLE_ROW_ALT]),
        ]))
        return t

    @staticmethod
    def _md_bold(text: str) -> str:
        """Konvertiert alle **fett** Vorkommen zu ReportLab <b>fett</b>."""
        return re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)

    def _markdown_to_story(self, text: str) -> list:
        """
        Konvertiert LLM-generierten Markdown-Text zu visuell strukturierten
        ReportLab-Elementen.

        Behandelt:
          - # / ##    → farbige Sektions-Banner (hellblau)
          - ### / #### → dunkle Sub-Banner
          - - / *     → Bullet-Gruppen mit Hintergrundfarbe (gesammelt)
          - 1. 2.     → Nummerierte Liste eingerückt
          - |...|     → echte ReportLab-Tabellen
          - ---       → horizontale Trennlinie
          - **text**  → Fettdruck
        """
        story = []
        b = self._md_bold

        lines = text.split('\n')
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()

            # ── Leerzeile ────────────────────────────────────────────────
            if not stripped:
                story.append(Spacer(1, 2*mm))
                i += 1

            # ── H1 / H2 → leichtes Banner (Blau, weniger dominant als SECTION_BG)
            elif stripped.startswith('## ') or stripped.startswith('# '):
                heading = stripped.lstrip('#').strip()
                p = Paragraph(b(heading), ParagraphStyle(
                    '_md_h1', parent=self.styles['SectionBanner'],
                    fontSize=10, spaceBefore=0, spaceAfter=0,
                ))
                t = Table([[p]], colWidths=[170*mm])
                t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#1e40af')),
                    ('TOPPADDING',    (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
                ]))
                story.append(Spacer(1, 3*mm))
                story.append(t)
                story.append(Spacer(1, 2*mm))
                i += 1

            # ── H3 / H4 → Sub-Banner (dunkelgrau-blau)
            elif stripped.startswith('#### ') or stripped.startswith('### '):
                heading = stripped.lstrip('#').strip()
                p = Paragraph(b(heading), ParagraphStyle(
                    '_md_h3', parent=self.styles['SectionBanner'],
                    fontSize=9, spaceBefore=0, spaceAfter=0,
                ))
                t = Table([[p]], colWidths=[170*mm])
                t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), colors.HexColor('#374151')),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
                ]))
                story.append(Spacer(1, 2*mm))
                story.append(t)
                story.append(Spacer(1, 1*mm))
                i += 1

            # ── Bullet-Liste → Gruppe sammeln und als Block rendern
            elif stripped.startswith('- ') or stripped.startswith('* '):
                bullet_items = []
                while i < len(lines) and (
                    lines[i].strip().startswith('- ') or lines[i].strip().startswith('* ')
                ):
                    bullet_items.append(b(lines[i].strip()[2:]))
                    i += 1
                story.append(self._md_bullet_block(bullet_items))
                story.append(Spacer(1, 1*mm))

            # ── Nummerierte Liste
            elif re.match(r'^\d+\.\s+', stripped):
                m = re.match(r'^(\d+)\.\s+(.*)', stripped)
                if m:
                    story.append(Paragraph(
                        f'<b>{m.group(1)}.</b>  {b(m.group(2))}',
                        self.styles['Body']
                    ))
                i += 1

            # ── Markdown-Tabelle → echte ReportLab-Tabelle
            elif stripped.startswith('|'):
                table_lines = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    table_lines.append(lines[i].strip())
                    i += 1
                # Header (erste Zeile), Separator (zweite), Daten (Rest)
                if len(table_lines) >= 2:
                    header_cells = [c.strip() for c in table_lines[0].strip('|').split('|') if c.strip()]
                    data_rows = []
                    for tl in table_lines[2:]:  # erste zwei = Header + Separator
                        if re.match(r'^\|[\s\-:|]+\|', tl):
                            continue
                        cells = [c.strip() for c in tl.strip('|').split('|')]
                        if any(cells):
                            data_rows.append([b(c) for c in cells])
                    if header_cells:
                        story.append(Spacer(1, 2*mm))
                        story.append(self._md_table(header_cells, data_rows))
                        story.append(Spacer(1, 2*mm))

            # ── Trennlinie
            elif stripped in ('---', '***', '___'):
                story.append(Spacer(1, 2*mm))
                story.append(HRFlowable(width='100%', color=BORDER_COLOR, thickness=0.5))
                story.append(Spacer(1, 2*mm))
                i += 1

            # ── Normaler Fließtext
            else:
                story.append(Paragraph(b(stripped), self.styles['Body']))
                i += 1

        return story

    def _build_reporter_sektion(self, data: Dict) -> list:
        """Sektion 9: KI-Forensischer Analysebericht (Reporter-Agent Output)."""
        story = []
        agent_analysis = data.get('agent_analysis') or {}
        reporter_text = agent_analysis.get('reporter') or ''

        story.append(self._section_banner('9. KI-Forensischer Analysebericht'))
        story.append(Spacer(1, 3*mm))

        ts = (agent_analysis.get('timestamp') or '')[:19].replace('T', ' ')
        story.append(self._agent_info_box(
            agent_label='Reporter-Agent (LFX Multi-Agent System)',
            agent_desc=(
                'Dieser Abschnitt wurde vollständig durch den KI-Reporter-Agenten generiert. '
                'Er fasst die Erkenntnisse aller drei Agenten (Triage, Analyst, Reporter) '
                'zu einem strukturierten forensischen Analysebericht zusammen.'
            ),
            ts=ts,
        ))
        story.append(Spacer(1, 5*mm))

        if reporter_text:
            story.extend(self._markdown_to_story(reporter_text))
        else:
            story.append(Paragraph(
                'Kein Reporter-Ergebnis verfügbar. Starte eine Analyse mit aktivierter '
                'Multi-Agent-Option um diesen Abschnitt zu füllen.',
                self.styles['Body']
            ))

        story.append(Spacer(1, 6*mm))
        return story

    def _build_anhang(self, data: Dict) -> list:
        """Anhang A (Triage) + Anhang B (DFIR-Analyst)."""
        story = []
        agent_analysis = data.get('agent_analysis') or {}
        ts = (agent_analysis.get('timestamp') or '')[:19].replace('T', ' ')

        # ── Anhang A: Triage ──────────────────────────────────────────────
        story.append(PageBreak())
        story.append(self._section_banner(
            'Anhang A: Triage-Klassifizierung (SOC Level 1)',
            color=colors.HexColor('#1e3a5f'),
        ))
        story.append(Spacer(1, 3*mm))
        story.append(self._agent_info_box(
            agent_label='SOC Level 1 Triage-Agent',
            agent_desc=(
                'Erstellt eine schnelle Erstbewertung aller erkannten Anomalien: '
                'Priorität (P1–P4), empfohlene Sofortmaßnahmen und Eskalationsentscheidung. '
                'Dient als Eingabe für den Senior DFIR Analyst-Agenten.'
            ),
            ts=ts,
        ))
        story.append(Spacer(1, 5*mm))
        triage_text = agent_analysis.get('triage') or ''
        if triage_text:
            story.extend(self._markdown_to_story(triage_text))
        else:
            story.append(Paragraph('Kein Triage-Ergebnis verfügbar.', self.styles['Body']))

        # ── Anhang B: DFIR-Analyst ────────────────────────────────────────
        story.append(PageBreak())
        story.append(self._section_banner(
            'Anhang B: DFIR-Tiefenanalyse (Senior Analyst)',
            color=colors.HexColor('#1e3a5f'),
        ))
        story.append(Spacer(1, 3*mm))
        story.append(self._agent_info_box(
            agent_label='Senior DFIR Analyst-Agent',
            agent_desc=(
                'Führt eine tiefgehende Korrelationsanalyse durch: Angriffsketten-Rekonstruktion, '
                'Lateral-Movement-Erkennung, persistente Hintertüren und detailliertes '
                'MITRE ATT&CK Mapping. Nutzt die Triage-Ergebnisse als Kontext.'
            ),
            ts=ts,
        ))
        story.append(Spacer(1, 5*mm))
        analyst_text = agent_analysis.get('analyst') or ''
        if analyst_text:
            story.extend(self._markdown_to_story(analyst_text))
        else:
            story.append(Paragraph('Kein Analyst-Ergebnis verfügbar.', self.styles['Body']))

        story.append(Spacer(1, 6*mm))
        return story

    def generate_full(self, output_path: Path, job_data: Dict) -> Path:
        """
        Generiert den vollständigen PDF-Report inkl. Multi-Agent Analyse.
        Sektion 9: Reporter-Agent Output.
        Anhang A/B: Triage + DFIR-Analyst Outputs.
        Sachverständigen-Erklärung bleibt letzte Seite.
        """
        pdf_path = output_path / 'forensic_full_report.pdf'

        kwargs = dict(
            pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=25*mm, bottomMargin=20*mm,
        )
        if HAS_ENCRYPTION:
            kwargs['encrypt'] = StandardEncryption(
                userPassword='',
                ownerPassword='lfw-forensic-readonly',
                canModify=0,
                canPrint=1,
                canCopy=1,
            )

        doc = SimpleDocTemplate(str(pdf_path), **kwargs)

        story = []
        story.extend(self._build_cover(job_data))
        story.append(PageBreak())
        story.extend(self._build_auftrag_sektion(job_data))
        story.extend(self._build_chain_of_custody(job_data))
        story.extend(self._build_executive_summary(job_data))
        story.extend(self._build_anomalies_table(job_data))
        story.extend(self._build_provenance_table(job_data))
        story.extend(self._build_mitre_summary(job_data))
        story.extend(self._build_ioc_list(job_data))
        story.extend(self._build_methodology())
        story.extend(self._build_limitationen())
        # NEU: Reporter-Sektion + Anhänge
        story.extend(self._build_reporter_sektion(job_data))
        story.extend(self._build_anhang(job_data))
        story.append(PageBreak())
        story.extend(self._build_sachverstaendigen_erklaerung(job_data))

        doc.build(story, onFirstPage=self._page_header_footer, onLaterPages=self._page_header_footer)
        logger.info(f"Vollständiger PDF-Report generiert: {pdf_path}")
        return pdf_path

    def _build_sachverstaendigen_erklaerung(self, data: Dict) -> list:
        """Sachverstaendigen-Erklaerung gemaess § 79 StPO / § 410 ZPO (letzte Seite)."""
        story = []
        story.append(Spacer(1, 30*mm))
        story.append(HRFlowable(width='100%', color=BORDER_COLOR))
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph(
            'ERKLÄRUNG DES SACHVERSTÄNDIGEN',
            self.styles['CoverTitle']
        ))
        story.append(Paragraph(
            'gemäß § 79 StPO / § 410 ZPO',
            self.styles['CoverSubtitle']
        ))
        story.append(Spacer(1, 10*mm))
        story.append(Paragraph(
            'Ich versichere, dass ich dieses Gutachten nach bestem Wissen und Gewissen erstellt habe, '
            'die Wahrheit gesagt und nichts verschwiegen habe. '
            'Mir sind keine Umstände bekannt, die meine Unabhängigkeit oder Unparteilichkeit '
            'beeinträchtigen könnten.',
            self.styles['Body']
        ))
        story.append(Spacer(1, 8*mm))

        erklaerung_rows = [
            ['Name', data.get('analyst', 'Nicht angegeben')],
            ['Qualifikation', data.get('qualifikation', 'Nicht angegeben')],
            ['Erstellungsdatum', datetime.now().strftime('%d.%m.%Y')],
        ]
        t = Table(erklaerung_rows, colWidths=[50*mm, 110*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_SECONDARY),
            ('BACKGROUND', (0, 0), (-1, -1), TABLE_ROW_ALT),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ]))
        story.append(t)
        story.append(Spacer(1, 15*mm))

        # Unterschriftszeilen (dynamisch wenn vom Frontend übergeben)
        ort_datum    = data.get('ort_datum', '')    or '___________________________'
        unterschrift = data.get('unterschrift', '') or '___________________________'
        sig_rows = [
            ['Ort, Datum:', ort_datum, 'Unterschrift:', unterschrift],
        ]
        ts = Table(sig_rows, colWidths=[25*mm, 55*mm, 25*mm, 55*mm])
        ts.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (-1, -1), TEXT_SECONDARY),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ts)

        story.append(Spacer(1, 10*mm))
        story.append(HRFlowable(width='100%', color=BORDER_COLOR))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            'Hinweis: In einer Produktivumgebung ist eine qualifizierte elektronische Signatur '
            'gemäß Art. 26 eIDAS-Verordnung (Verordnung (EU) Nr. 910/2014) erforderlich.',
            self.styles['Small']
        ))
        return story


# ═════════════════════════════════════════════════════════════════════════════
# Case-Korrelations-PDF
# ═════════════════════════════════════════════════════════════════════════════

ACCENT_CYAN = colors.HexColor('#06b6d4')


class CasePDFGenerator:
    """Generiert Fall-uebergreifende Korrelations-PDF-Reports."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.page_width, self.page_height = A4

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='CoverTitle', fontSize=26, leading=32,
            textColor=TEXT_PRIMARY, alignment=TA_CENTER,
            spaceAfter=10, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CoverSubtitle', fontSize=12, leading=16,
            textColor=TEXT_SECONDARY, alignment=TA_CENTER, spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle', fontSize=14, leading=18,
            textColor=TEXT_PRIMARY, spaceBefore=16, spaceAfter=8,
            fontName='Helvetica-Bold', keepWithNext=1,
        ))
        self.styles.add(ParagraphStyle(
            name='SubSection', fontSize=11, leading=14,
            textColor=TEXT_PRIMARY, spaceBefore=10, spaceAfter=5,
            fontName='Helvetica-Bold', keepWithNext=1,
        ))
        self.styles.add(ParagraphStyle(
            name='Body', fontSize=9, leading=13,
            textColor=TEXT_SECONDARY, spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name='Small', fontSize=8, leading=10,
            textColor=TEXT_SECONDARY,
        ))
        self.styles.add(ParagraphStyle(
            name='Footer', fontSize=7, leading=9,
            textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER,
        ))
        self.styles.add(ParagraphStyle(
            name='CellDefault', fontSize=7, leading=9,
            textColor=TEXT_SECONDARY,
        ))
        self.styles.add(ParagraphStyle(
            name='CellHeader', fontSize=7, leading=9,
            textColor=colors.white, fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='CellCyan', fontSize=7, leading=9,
            textColor=ACCENT_CYAN,
        ))
        self.styles.add(ParagraphStyle(
            name='CellPurple', fontSize=7, leading=9,
            textColor=ACCENT_PURPLE,
        ))
        self.styles.add(ParagraphStyle(
            name='ReportBody', fontSize=9, leading=13,
            textColor=TEXT_SECONDARY, spaceAfter=3,
        ))
        self.styles.add(ParagraphStyle(
            name='ReportHeading', fontSize=11, leading=14,
            textColor=TEXT_PRIMARY, spaceBefore=8, spaceAfter=4,
            fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='SectionBanner', fontSize=11, leading=14,
            textColor=colors.white, fontName='Helvetica-Bold',
            spaceBefore=12, spaceAfter=6, leftIndent=6,
        ))

    def _section_banner(self, text: str, color=None) -> Table:
        """Farbiges Sektions-Banner — identisch zu ForensicPDFGenerator."""
        bg = color or SECTION_BG
        p = Paragraph(text, self.styles['SectionBanner'])
        t = Table([[p]], colWidths=[170*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), bg),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return t

    def generate(self, output_path: Path, case_data: Dict) -> Path:
        """Generiert den Fall-Korrelations-PDF-Report."""
        pdf_path = output_path / 'case_correlation_report.pdf'

        doc = SimpleDocTemplate(
            str(pdf_path), pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=25*mm, bottomMargin=20*mm,
        )

        story = []
        story.extend(self._build_case_cover(case_data))
        story.append(PageBreak())
        story.extend(self._build_case_overview(case_data))
        story.extend(self._build_shared_iocs_table(case_data))
        story.extend(self._build_per_source_summary(case_data))
        story.extend(self._build_combined_mitre(case_data))
        story.extend(self._build_correlation_report(case_data))
        story.extend(self._build_methodology())

        doc.build(story, onFirstPage=self._page_header_footer, onLaterPages=self._page_header_footer)
        logger.info(f"Case-PDF-Report generiert: {pdf_path}")
        return pdf_path

    def _page_header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.drawString(20*mm, self.page_height - 15*mm, 'LFX Forensic Analysis System — Fall-Korrelation')
        canvas.drawRightString(self.page_width - 20*mm, self.page_height - 15*mm, 'VERTRAULICH')
        canvas.setStrokeColor(BORDER_COLOR)
        canvas.line(20*mm, self.page_height - 17*mm, self.page_width - 20*mm, self.page_height - 17*mm)
        canvas.drawCentredString(self.page_width / 2, 12*mm, f'Seite {doc.page}')
        canvas.drawRightString(self.page_width - 20*mm, 12*mm, datetime.now().strftime('%d.%m.%Y'))
        canvas.restoreState()

    def _build_case_cover(self, data: Dict) -> list:
        story = []
        story.append(Spacer(1, 80*mm))
        story.append(Paragraph('FALL-KORRELATIONS-<br/>ANALYSEBERICHT', self.styles['CoverTitle']))
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph('LFX Forensic Analysis System', self.styles['CoverSubtitle']))
        story.append(Spacer(1, 20*mm))

        meta = data.get('metadata', {})
        meta_rows = [
            ['Datum', datetime.now().strftime('%d.%m.%Y %H:%M')],
            ['Fallname', data.get('case_name', 'Unbekannt')],
            ['Aktenzeichen', data.get('case_number', '') or '—'],
            ['Analyst', data.get('analyst', '') or '—'],
            ['Quellen analysiert', str(meta.get('sources_count', len(data.get('sources', []))))],
            ['Anomalien gesamt', str(meta.get('total_anomalies', 0))],
            ['Events gesamt', str(meta.get('total_events', 0))],
            ['Gemeinsame IOCs', str(meta.get('shared_iocs_count', 0))],
        ]

        t = Table(meta_rows, colWidths=[50*mm, 80*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (0, -1), 'Helvetica-Bold', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica', 9),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_SECONDARY),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)

        story.append(Spacer(1, 30*mm))
        story.append(Paragraph(
            'Vertraulich — Nur fuer autorisierten Gebrauch',
            self.styles['Footer']
        ))
        return story

    def _build_case_overview(self, data: Dict) -> list:
        story = []
        story.append(self._section_banner('1. Fall-Übersicht'))

        sources = data.get('sources', [])
        meta = data.get('metadata', {})

        story.append(Paragraph(
            f'Dieser Bericht fasst die quellenuebergreifende Korrelationsanalyse von '
            f'<b>{len(sources)} forensischen Quellen</b> zusammen. '
            f'Insgesamt wurden <b>{meta.get("total_events", 0)} Events</b> mit '
            f'<b>{meta.get("total_anomalies", 0)} Anomalien</b> analysiert. '
            f'Es wurden <b>{meta.get("shared_iocs_count", 0)} quellenuebergreifende IOCs</b> identifiziert.',
            self.styles['Body']
        ))
        story.append(Spacer(1, 5*mm))
        return story

    def _build_shared_iocs_table(self, data: Dict) -> list:
        story = []
        shared_iocs = data.get('shared_iocs', {})
        has_shared = any(v for v in shared_iocs.values())
        if not has_shared:
            return story

        story.append(self._section_banner('2. Quellenübergreifende IOCs'))

        sources = data.get('sources', [])
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_c = self.styles['CellCyan']

        label_map = {
            'ips': 'IP-Adressen', 'users': 'Benutzer', 'hostnames': 'Hostnamen',
            'domains': 'Domains', 'processes': 'Prozesse', 'files': 'Dateien',
        }

        for category, vals in shared_iocs.items():
            if not vals:
                continue

            story.append(Paragraph(f'Gemeinsame {label_map.get(category, category)}:', self.styles['SubSection']))

            header = [Paragraph('IOC', cell_h), Paragraph('Gefunden in Quellen', cell_h)]
            rows = [header]

            for val, source_indices in vals.items():
                source_names = []
                for idx in source_indices:
                    if idx < len(sources):
                        s = sources[idx].get('summary', {})
                        name = s.get('input_file', f'Quelle {idx + 1}')
                        if '\\' in name or '/' in name:
                            from pathlib import Path as P
                            name = P(name).name
                    else:
                        name = f'Quelle {idx + 1}'
                    source_names.append(name)

                rows.append([
                    Paragraph(str(val)[:60], cell_c),
                    Paragraph(', '.join(source_names), cell_d),
                ])

            t = Table(rows, colWidths=[60*mm, 100*mm], repeatRows=1)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
                ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(t)
            story.append(Spacer(1, 3*mm))

        story.append(Spacer(1, 5*mm))
        return story

    def _build_per_source_summary(self, data: Dict) -> list:
        story = []
        sources = data.get('sources', [])
        if not sources:
            return story

        story.append(self._section_banner('3. Analysierte Quellen'))

        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']

        header = [
            Paragraph('Nr', cell_h),
            Paragraph('Datei', cell_h),
            Paragraph('Typ', cell_h),
            Paragraph('Events', cell_h),
            Paragraph('Anomalien', cell_h),
            Paragraph('IOCs', cell_h),
        ]
        rows = [header]

        for i, src in enumerate(sources, 1):
            s = src.get('summary', {})
            name = s.get('input_file', f'Quelle {i}')
            if '\\' in name or '/' in name:
                from pathlib import Path as P
                name = P(name).name
            rows.append([
                Paragraph(str(i), cell_d),
                Paragraph(name[:40], cell_d),
                Paragraph(s.get('input_type', '?'), cell_d),
                Paragraph(str(s.get('total_events', 0)), cell_d),
                Paragraph(str(len(src.get('anomalies', []))), cell_d),
                Paragraph(str(s.get('iocs_identified', 0)), cell_d),
            ])

        t = Table(rows, colWidths=[10*mm, 55*mm, 25*mm, 20*mm, 25*mm, 18*mm], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))
        return story

    def _build_combined_mitre(self, data: Dict) -> list:
        story = []
        sources = data.get('sources', [])

        technique_map: Dict[str, Dict] = {}
        for i, src in enumerate(sources):
            for a in src.get('anomalies', []):
                for t in a.get('mitre_techniques', []):
                    tid = t.get('id', '?')
                    if tid not in technique_map:
                        technique_map[tid] = {
                            'id': tid, 'name': t.get('name', '?'),
                            'tactic': t.get('tactic', '?'), 'sources': set(), 'count': 0,
                        }
                    technique_map[tid]['sources'].add(i + 1)
                    technique_map[tid]['count'] += 1

        if not technique_map:
            return story

        story.append(self._section_banner('4. MITRE ATT&CK — Kombinierte Zuordnung'))

        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_p = self.styles['CellPurple']

        header = [
            Paragraph('Technik-ID', cell_h),
            Paragraph('Name', cell_h),
            Paragraph('Taktik', cell_h),
            Paragraph('Quellen', cell_h),
            Paragraph('Anzahl', cell_h),
        ]
        rows = [header]

        for tech in sorted(technique_map.values(), key=lambda x: x['count'], reverse=True)[:20]:
            src_str = ', '.join(str(s) for s in sorted(tech['sources']))
            rows.append([
                Paragraph(tech['id'], cell_p),
                Paragraph(tech['name'], cell_d),
                Paragraph(tech['tactic'], cell_d),
                Paragraph(src_str, cell_d),
                Paragraph(str(tech['count']), cell_d),
            ])

        t = Table(rows, colWidths=[25*mm, 45*mm, 35*mm, 25*mm, 18*mm], repeatRows=1)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))
        return story

    def _build_correlation_report(self, data: Dict) -> list:
        story = []
        report = data.get('correlation_report', '')
        if not report:
            return story

        story.append(self._section_banner('5. KI-Korrelationsanalyse'))

        # Markdown in einfache Paragraphs umwandeln
        for line in report.split('\n'):
            stripped = line.strip()
            if not stripped:
                story.append(Spacer(1, 2*mm))
            elif stripped.startswith('# '):
                story.append(Paragraph(stripped[2:], self.styles['SectionTitle']))
            elif stripped.startswith('## '):
                story.append(Paragraph(stripped[3:], self.styles['ReportHeading']))
            elif stripped.startswith('### '):
                story.append(Paragraph(stripped[4:], self.styles['SubSection']))
            elif stripped.startswith('- ') or stripped.startswith('* '):
                story.append(Paragraph(f'&bull;  {stripped[2:]}', self.styles['ReportBody']))
            elif stripped.startswith('|'):
                # Tabellen-Zeilen ueberspringen (werden nicht gut in PDF gerendert)
                continue
            else:
                # Bold-Markdown konvertieren
                text = stripped.replace('**', '<b>', 1)
                if '<b>' in text:
                    text = text.replace('**', '</b>', 1)
                story.append(Paragraph(text, self.styles['ReportBody']))

        story.append(Spacer(1, 5*mm))
        return story

    def _build_methodology(self) -> list:
        story = []
        story.append(self._section_banner('6. Methodologie'))
        story.append(Paragraph(
            'Dieser Fall-Korrelationsbericht wurde automatisch durch das LFX Forensic Analysis System generiert. '
            'Die quellenuebergreifende Analyse umfasst:', self.styles['Body']
        ))
        methods = [
            '<b>IOC-Kreuzabgleich:</b> Automatischer Abgleich aller Indicators of Compromise '
            'ueber alle analysierten Quellen zur Identifikation gemeinsamer Bedrohungsindikatoren.',
            '<b>MITRE ATT&CK Aggregation:</b> Zusammenfuehrung aller MITRE-Techniken aus '
            'einzelnen Analysen zu einer quellenuebergreifenden Angriffskette.',
            '<b>KI-Korrelationsanalyse:</b> LLM-basierte Analyse (Ollama) zur Identifikation '
            'zeitlicher Muster, Angriffsketten und quellenuebergreifender Zusammenhaenge.',
        ]
        for m in methods:
            story.append(Paragraph(f'&bull;  {m}', self.styles['Body']))

        story.append(Spacer(1, 8*mm))
        story.append(HRFlowable(width='100%', color=BORDER_COLOR))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            'LFX Forensic Analysis System v1.1 — Fall-Korrelation generiert am '
            + datetime.now().strftime('%d.%m.%Y um %H:%M Uhr'),
            self.styles['Footer']
        ))
        return story
