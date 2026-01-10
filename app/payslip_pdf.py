"""
PDF Payslip Generator for WAGEPRO
Generates professional payslip PDFs with loan and deduction breakdowns
"""

import os
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
from app.sa_public_holidays import is_public_holiday


def generate_payslip_pdf(payslip_data, output_path):
    """
    Generate a professional payslip PDF

    Args:
        payslip_data: Dictionary containing payslip information
        output_path: Full path where PDF should be saved

    Returns:
        str: Path to generated PDF file
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Create PDF document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.5*inch,
        leftMargin=0.5*inch,
        topMargin=0.5*inch,
        bottomMargin=0.5*inch
    )

    # Container for PDF elements
    elements = []

    # Styles - reduced by 50%
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=10,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=7,
        textColor=colors.HexColor('#374151'),
        spaceAfter=3,
        spaceBefore=6,
        fontName='Helvetica-Bold'
    )

    # Title with Staff Name and ID
    staff_name = payslip_data.get('staff_name', 'Unknown')
    staff_id = payslip_data.get('staff_id', '')
    title_text = f"PAYSLIP - {staff_name.upper()} #{staff_id}"
    elements.append(Paragraph(title_text, title_style))
    elements.append(Spacer(1, 0.08*inch))

    # Simplified Info Table - Only Pay Period and Payment Date
    info_data = [
        ['Pay Period:', f"{payslip_data.get('pay_period_start', 'N/A')} to {payslip_data.get('pay_period_end', 'N/A')}", 'Payment Date:', payslip_data.get('paid_at', 'Not Paid')],
    ]

    info_table = Table(info_data, colWidths=[0.9*inch, 1.5*inch, 0.9*inch, 1.0*inch])
    info_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 0.1*inch))

    # Days Worked Section
    elements.append(Paragraph("DAYS WORKED (2-Week Pay Period)", heading_style))

    # Calculate actual dates for the 2-week period
    start_date = datetime.strptime(payslip_data.get('pay_period_start', '01/01/2025'), '%d/%m/%Y').date()

    # Week 1 dates (Mon-Sun)
    w1_dates = []
    current_date = start_date
    # Find first Monday
    while current_date.weekday() != 0:  # 0 = Monday
        current_date += timedelta(days=1)
    # Get 7 days starting from Monday
    for i in range(7):
        w1_dates.append(current_date + timedelta(days=i))

    # Week 2 dates (next 7 days)
    w2_dates = [w1_dates[-1] + timedelta(days=i+1) for i in range(7)]

    # Build days table with dates and public holiday markers
    days_data = [
        ['Week 1', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat*', 'Sun*'],
        [''] + [d.strftime('%d/%m') + ('*' if is_public_holiday(d) else '') for d in w1_dates],
        ['',
         '✓' if payslip_data.get('w1_monday') else '-',
         '✓' if payslip_data.get('w1_tuesday') else '-',
         '✓' if payslip_data.get('w1_wednesday') else '-',
         '✓' if payslip_data.get('w1_thursday') else '-',
         '✓' if payslip_data.get('w1_friday') else '-',
         '✓' if payslip_data.get('w1_saturday') else '-',
         '✓' if payslip_data.get('w1_sunday') else '-'],
        ['Week 2', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat*', 'Sun*'],
        [''] + [d.strftime('%d/%m') + ('*' if is_public_holiday(d) else '') for d in w2_dates],
        ['',
         '✓' if payslip_data.get('w2_monday') else '-',
         '✓' if payslip_data.get('w2_tuesday') else '-',
         '✓' if payslip_data.get('w2_wednesday') else '-',
         '✓' if payslip_data.get('w2_thursday') else '-',
         '✓' if payslip_data.get('w2_friday') else '-',
         '✓' if payslip_data.get('w2_saturday') else '-',
         '✓' if payslip_data.get('w2_sunday') else '-'],
    ]

    days_table = Table(days_data, colWidths=[0.5*inch] + [0.4*inch]*7)
    days_table.setStyle(TableStyle([
        # Week 1 header
        ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#e0f2fe')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        # Week 1 dates row
        ('FONTSIZE', (1, 1), (-1, 1), 4),
        ('TEXTCOLOR', (1, 1), (-1, 1), colors.HexColor('#6b7280')),
        # Week 2 header
        ('BACKGROUND', (0, 3), (0, 3), colors.HexColor('#e0f2fe')),
        ('FONTNAME', (0, 3), (-1, 3), 'Helvetica-Bold'),
        # Week 2 dates row
        ('FONTSIZE', (1, 4), (-1, 4), 4),
        ('TEXTCOLOR', (1, 4), (-1, 4), colors.HexColor('#6b7280')),
        # General styling
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
    ]))
    elements.append(days_table)
    elements.append(Spacer(1, 0.08*inch))

    # Add weekend pay rule explanation
    rule_style = ParagraphStyle(
        'RuleText',
        parent=styles['Normal'],
        fontSize=4,
        textColor=colors.HexColor('#4b5563'),
        alignment=TA_LEFT,
        spaceAfter=3,
        spaceBefore=0,
        leftIndent=0
    )
    rule_text = "<i>Note: Sat/Sun paid at 1.5x rate if 3+ weekdays worked in that week, otherwise 1.0x rate. Public holidays (*) paid at 1.5x rate.</i>"
    elements.append(Paragraph(rule_text, rule_style))
    elements.append(Spacer(1, 0.08*inch))

    # Earnings Breakdown
    elements.append(Paragraph("EARNINGS", heading_style))

    earnings_data = [
        ['Description', 'Amount'],
        ['Weekday Pay', f"R {payslip_data.get('weekday_pay', 0.0):.2f}"],
        ['Weekend Pay', f"R {payslip_data.get('weekend_pay', 0.0):.2f}"],
    ]

    if payslip_data.get('public_holiday_pay', 0) > 0:
        earnings_data.append(['Public Holiday Pay (1.5x)', f"R {payslip_data.get('public_holiday_pay', 0.0):.2f}"])

    if payslip_data.get('overtime_pay', 0) > 0:
        earnings_data.append(['Overtime Pay', f"R {payslip_data.get('overtime_pay', 0.0):.2f}"])

    if payslip_data.get('bonus', 0) > 0:
        earnings_data.append(['Bonus', f"R {payslip_data.get('bonus', 0.0):.2f}"])

    earnings_data.append(['GROSS PAY', f"R {payslip_data.get('gross_pay', 0.0):.2f}"])

    earnings_table = Table(earnings_data, colWidths=[2.5*inch, 1*inch])
    earnings_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#dbeafe')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('FONTSIZE', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(earnings_table)
    elements.append(Spacer(1, 0.1*inch))

    # Deductions Breakdown
    elements.append(Paragraph("DEDUCTIONS", heading_style))

    deductions_data = [['Description', 'Amount']]

    # Add loans
    if payslip_data.get('loans'):
        for loan in payslip_data['loans']:
            deductions_data.append([
                f"Loan: {loan.get('description', 'N/A')}",
                f"-R {loan.get('installment_amount', 0.0):.2f}"
            ])

    # Add other deductions
    if payslip_data.get('deductions'):
        for deduction in payslip_data['deductions']:
            badge = ' (ONCE OFF)' if deduction.get('deduction_type') == 'once_off' else ''
            deductions_data.append([
                f"{deduction.get('description', 'N/A')}{badge}",
                f"-R {deduction.get('amount', 0.0):.2f}"
            ])

    # Add savings
    if payslip_data.get('savings_deduction', 0) > 0:
        deductions_data.append([
            'Savings Deposit',
            f"-R {payslip_data.get('savings_deduction', 0.0):.2f}"
        ])

    # Total deductions
    deductions_data.append(['TOTAL DEDUCTIONS', f"-R {payslip_data.get('total_deductions', 0.0):.2f}"])

    deductions_table = Table(deductions_data, colWidths=[2.5*inch, 1*inch])
    deductions_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#fee2e2')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('FONTSIZE', (0, 0), (-1, -1), 5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(deductions_table)
    elements.append(Spacer(1, 0.1*inch))

    # Net Pay (Take Home)
    net_pay_data = [
        ['NET PAY (Take Home)', f"R {payslip_data.get('net_pay', 0.0):.2f}"]
    ]

    net_pay_table = Table(net_pay_data, colWidths=[2.5*inch, 1*inch])
    net_pay_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#10b981')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
    ]))
    elements.append(net_pay_table)
    elements.append(Spacer(1, 0.15*inch))

    # Loan & Savings Summary Section
    if payslip_data.get('total_loan_balance', 0) > 0 or payslip_data.get('savings_balance', 0) > 0:
        elements.append(Paragraph("ACCOUNT SUMMARY", heading_style))

        summary_data = [['Account Type', 'Balance', 'This Period']]

        # Loan Summary - find the row index for styling
        loan_row = None
        if payslip_data.get('total_loan_balance', 0) > 0:
            loan_row = len(summary_data)
            summary_data.append([
                'Outstanding Loans (OWED BY YOU)',
                f"R {payslip_data.get('total_loan_balance', 0.0):.2f}",
                f"-R {payslip_data.get('total_loan_repayment', 0.0):.2f}"
            ])

        # Savings Summary - find the row index for styling
        savings_row = None
        if payslip_data.get('savings_balance', 0) > 0:
            savings_row = len(summary_data)
            summary_data.append([
                'Savings Account (YOUR MONEY)',
                f"R {payslip_data.get('savings_balance', 0.0):.2f}",
                f"+R {payslip_data.get('savings_deduction', 0.0):.2f}"
            ])

        summary_table = Table(summary_data, colWidths=[1.5*inch, 1*inch, 1*inch])

        # Build style list dynamically
        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f4f6')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
            ('FONTSIZE', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
        ]

        # Add red styling for loan row (entire row background + bold white text)
        if loan_row is not None:
            style_commands.extend([
                ('BACKGROUND', (0, loan_row), (-1, loan_row), colors.HexColor('#fee2e2')),
                ('TEXTCOLOR', (0, loan_row), (-1, loan_row), colors.HexColor('#991b1b')),
                ('FONTNAME', (0, loan_row), (-1, loan_row), 'Helvetica-Bold'),
            ])

        # Add green styling for savings row (entire row background + bold text)
        if savings_row is not None:
            style_commands.extend([
                ('BACKGROUND', (0, savings_row), (-1, savings_row), colors.HexColor('#d1fae5')),
                ('TEXTCOLOR', (0, savings_row), (-1, savings_row), colors.HexColor('#065f46')),
                ('FONTNAME', (0, savings_row), (-1, savings_row), 'Helvetica-Bold'),
            ])

        summary_table.setStyle(TableStyle(style_commands))
        elements.append(summary_table)
        elements.append(Spacer(1, 0.1*inch))

    # Footer
    elements.append(Spacer(1, 0.2*inch))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=4,
        textColor=colors.grey,
        alignment=TA_CENTER
    )
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%d/%m/%Y at %H:%M')}", footer_style))
    elements.append(Paragraph("This is a computer-generated document. No signature required.", footer_style))

    # Build PDF
    doc.build(elements)

    return output_path
