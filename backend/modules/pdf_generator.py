"""
PDF Report Generator.

Erstellt professionelle forensische Berichte im PDF-Format mit ReportLab.
Deckblatt, Executive Summary, MITRE-Mapping, Anomalien-Tabelle, IOC-Liste.
"""

import logging
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
            fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='SubSection', fontSize=11, leading=14,
            textColor=TEXT_PRIMARY, spaceBefore=10, spaceAfter=5,
            fontName='Helvetica-Bold',
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

    def generate(self, output_path: Path, job_data: Dict) -> Path:
        """Generiert den vollstaendigen PDF-Report."""
        pdf_path = output_path / 'forensic_report.pdf'

        doc = SimpleDocTemplate(
            str(pdf_path), pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=25*mm, bottomMargin=20*mm,
        )

        story = []
        story.extend(self._build_cover(job_data))
        story.append(PageBreak())
        story.extend(self._build_executive_summary(job_data))
        story.extend(self._build_anomalies_table(job_data))
        story.extend(self._build_mitre_summary(job_data))
        story.extend(self._build_ioc_list(job_data))
        story.extend(self._build_methodology())

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

    def _build_cover(self, data: Dict) -> list:
        """Deckblatt."""
        story = []
        story.append(Spacer(1, 80*mm))
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

        # SHA256-Hash wenn vorhanden
        if data.get('file_hash'):
            meta_rows.append(['SHA256', data['file_hash']])

        # Case-Info wenn vorhanden
        if data.get('case_name'):
            meta_rows.insert(0, ['Fall', data['case_name']])
        if data.get('case_number'):
            meta_rows.insert(1, ['Aktenzeichen', data['case_number']])
        if data.get('analyst'):
            meta_rows.append(['Analyst', data['analyst']])

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
        """Executive Summary."""
        story = []
        story.append(Paragraph('1. Executive Summary', self.styles['SectionTitle']))

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

        # Metriken
        metrics = [
            ['Total Events', str(summary.get('total_events', 0)),
             'Anomalien', str(summary.get('anomalies_found', len(anomalies)))],
            ['IOCs', str(summary.get('iocs_identified', 0)),
             'Gesamtrisiko', risk_text.get(risk_level, 'UNBEKANNT')],
        ]
        t = Table(metrics, colWidths=[35*mm, 35*mm, 35*mm, 35*mm])
        t.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 9),
            ('FONT', (1, 0), (1, -1), 'Helvetica-Bold', 10),
            ('FONT', (3, 0), (3, -1), 'Helvetica-Bold', 10),
            ('TEXTCOLOR', (0, 0), (0, -1), TEXT_SECONDARY),
            ('TEXTCOLOR', (2, 0), (2, -1), TEXT_SECONDARY),
            ('TEXTCOLOR', (1, 0), (1, -1), TEXT_PRIMARY),
            ('TEXTCOLOR', (3, 1), (3, 1), RISK_COLORS.get(risk_level, TEXT_PRIMARY)),
            ('BACKGROUND', (0, 0), (-1, -1), TABLE_ROW_ALT),
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # Top-3 Findings
        if anomalies:
            story.append(Paragraph('Top Findings:', self.styles['SubSection']))
            top3 = sorted(anomalies, key=lambda a: a.get('anomaly_score', 0), reverse=True)[:3]
            for i, a in enumerate(top3, 1):
                desc = a.get('description', a.get('event', ''))[:120]
                score = a.get('anomaly_score', 0)
                mitre = ', '.join(t['id'] for t in a.get('mitre_techniques', [])[:2])
                line = f"<b>{i}.</b> [{score:.0%}] {desc}"
                if mitre:
                    line += f'  <font color="#a855f7">({mitre})</font>'
                story.append(Paragraph(line, self.styles['Body']))

        story.append(Spacer(1, 5*mm))
        return story

    def _build_anomalies_table(self, data: Dict) -> list:
        """Anomalien-Tabelle mit MITRE."""
        story = []
        anomalies = data.get('anomalies', [])
        if not anomalies:
            return story

        story.append(Paragraph('2. Erkannte Anomalien', self.styles['SectionTitle']))

        # Header mit Paragraph fuer konsistentes Rendering
        cell_h = self.styles['CellHeader']
        cell_d = self.styles['CellDefault']
        cell_p = self.styles['CellPurple']

        header = [
            Paragraph('Nr', cell_h),
            Paragraph('Zeitstempel', cell_h),
            Paragraph('Typ', cell_h),
            Paragraph('Score', cell_h),
            Paragraph('MITRE', cell_h),
            Paragraph('Beschreibung', cell_h),
        ]
        rows = [header]

        sorted_anomalies = sorted(anomalies, key=lambda a: a.get('anomaly_score', 0), reverse=True)
        for i, a in enumerate(sorted_anomalies[:30], 1):
            ts = a.get('timestamp', '—')[:19]
            etype = a.get('event_type', '—')[:20]
            score = f"{a.get('anomaly_score', 0):.0%}"
            mitre = ', '.join(t['id'] for t in a.get('mitre_techniques', [])[:2])
            desc = (a.get('description', '') or '')[:120]
            rows.append([
                Paragraph(str(i), cell_d),
                Paragraph(ts, cell_d),
                Paragraph(etype, cell_d),
                Paragraph(score, cell_d),
                Paragraph(mitre, cell_p),
                Paragraph(desc, cell_d),
            ])

        col_widths = [10*mm, 32*mm, 25*mm, 14*mm, 25*mm, 54*mm]
        t = Table(rows, colWidths=col_widths, repeatRows=1)

        style_commands = [
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
            # Grid
            ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, BORDER_COLOR),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]

        # Alternating row colors
        for i in range(1, len(rows)):
            if i % 2 == 0:
                style_commands.append(('BACKGROUND', (0, i), (-1, i), TABLE_ROW_ALT))

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

        story.append(Paragraph('3. MITRE ATT&CK Zuordnung', self.styles['SectionTitle']))

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

        story.append(Paragraph('4. Indicators of Compromise (IOCs)', self.styles['SectionTitle']))

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
        story.append(Paragraph('5. Methodologie', self.styles['SectionTitle']))
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
            'und verdaechtigen Dateipfaden aus den analysierten Events.',
        ]
        for m in methods:
            story.append(Paragraph(f'&bull;  {m}', self.styles['Body']))

        story.append(Spacer(1, 8*mm))
        story.append(HRFlowable(width='100%', color=BORDER_COLOR))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            'LFX Forensic Analysis System v1.1 — Generiert am ' + datetime.now().strftime('%d.%m.%Y um %H:%M Uhr'),
            self.styles['Footer']
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
            fontName='Helvetica-Bold',
        ))
        self.styles.add(ParagraphStyle(
            name='SubSection', fontSize=11, leading=14,
            textColor=TEXT_PRIMARY, spaceBefore=10, spaceAfter=5,
            fontName='Helvetica-Bold',
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
        story.append(Paragraph('1. Fall-Uebersicht', self.styles['SectionTitle']))

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

        story.append(Paragraph('2. Quellenuebergreifende IOCs', self.styles['SectionTitle']))

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

        story.append(Paragraph('3. Analysierte Quellen', self.styles['SectionTitle']))

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

        story.append(Paragraph('4. MITRE ATT&CK — Kombinierte Zuordnung', self.styles['SectionTitle']))

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

        story.append(Paragraph('5. KI-Korrelationsanalyse', self.styles['SectionTitle']))

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
        story.append(Paragraph('6. Methodologie', self.styles['SectionTitle']))
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
