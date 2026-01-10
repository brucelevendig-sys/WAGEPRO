"""
SMS Notification Module for WAGEPRO
Sends SMS to staff when payslips are verified
Uses WinSMS FTP gateway
"""

import os
from datetime import datetime, timedelta
from ftplib import FTP
from typing import List, Dict, Optional, Tuple

# WinSMS FTP Configuration
WINSMS_FTP_SERVER = 'ftp.winsms.co.za'
WINSMS_FTP_USER = 'drlevendig'
WINSMS_FTP_PASSWORD = '27rp3fg6'
WINSMS_SENDER_EMAIL = 'accounts@levendig.co.za'
WINSMS_SENDER_PASSWORD = '0826000sms'


class SMSNotifier:
    """Handle SMS notifications for payslip verification"""

    def __init__(self):
        """Initialize SMS Notifier with WinSMS credentials"""
        self.sms_account = WINSMS_SENDER_EMAIL
        self.sms_password = WINSMS_SENDER_PASSWORD
        self.batch_dir = "C:\\WAGEPRO\\sms_batches"

        # Create batch directory if it doesn't exist
        os.makedirs(self.batch_dir, exist_ok=True)

    def upload_to_winsms(self, batch_file_path: str) -> Tuple[bool, str]:
        """
        Upload batch file to WinSMS FTP server

        Args:
            batch_file_path: Path to the batch file

        Returns:
            Tuple of (success, message)
        """
        try:
            ftp = FTP(WINSMS_FTP_SERVER, timeout=30)
            ftp.login(WINSMS_FTP_USER, WINSMS_FTP_PASSWORD)

            with open(batch_file_path, 'rb') as f:
                ftp.storbinary('STOR MSGBATCH.TXT', f)

            ftp.quit()
            return True, "SMS batch uploaded successfully"
        except Exception as e:
            return False, f"FTP upload failed: {str(e)}"

    def create_batch_file(self, messages: List[Dict[str, str]], scheduled_time: datetime = None) -> Optional[str]:
        """
        Create SMS batch file in FoxPro format

        Args:
            messages: List of dicts with 'mobile' and 'message' keys
            scheduled_time: Optional datetime to schedule SMS (if None, sends immediately)

        Returns:
            Path to created batch file, or None if no messages
        """
        if not messages:
            return None

        # Generate timestamp for filename and credentials
        timestamp = datetime.now().strftime("%Y%m%d%H%M")
        batch_filename = f"SMSBATCH_{timestamp}.TXT"
        batch_path = os.path.join(self.batch_dir, batch_filename)

        try:
            with open(batch_path, 'w', encoding='utf-8') as f:
                # Line 1: Credentials with timestamp
                # If scheduled_time provided, add it as 5th field (WinSMS format: YYYYMMDDHHMM)
                if scheduled_time:
                    schedule_str = scheduled_time.strftime("%Y%m%d%H%M")
                    f.write(f'"{self.sms_account}","{self.sms_password}","{timestamp}","","{schedule_str}"\n')
                    print(f"[SMS] Scheduled for: {scheduled_time.strftime('%Y-%m-%d %H:%M')}")
                else:
                    f.write(f'"{self.sms_account}","{self.sms_password}","{timestamp}"\n')

                # Line 2+: Messages (one per recipient)
                for msg in messages:
                    mobile = msg.get('mobile', '').strip()
                    message = msg.get('message', '').strip()

                    # Skip if no mobile number
                    if not mobile:
                        continue

                    # Remove any non-numeric characters FIRST (strips + and spaces)
                    mobile = ''.join(c for c in mobile if c.isdigit())

                    # Ensure mobile number starts with 27 (South Africa)
                    if mobile.startswith('0'):
                        mobile = '27' + mobile[1:]
                    elif not mobile.startswith('27'):
                        mobile = '27' + mobile

                    # Write message line
                    f.write(f'"{mobile}","{message}"\n')

            print(f"[SMS] Batch file created: {batch_path}")
            print(f"[SMS] {len(messages)} message(s) queued")
            return batch_path

        except Exception as e:
            print(f"[ERROR] Failed to create SMS batch file: {e}")
            return None

    def create_bat_runner(self, batch_file_path: str) -> Optional[str]:
        """
        Create .BAT file to process the SMS batch

        Args:
            batch_file_path: Path to the SMSBATCH.TXT file

        Returns:
            Path to created .BAT file
        """
        bat_filename = batch_file_path.replace('.TXT', '.BAT')

        try:
            with open(bat_filename, 'w') as f:
                f.write('@echo off\n')
                f.write('REM ================================================================\n')
                f.write('REM WAGEPRO - SMS BATCH PROCESSOR\n')
                f.write('REM ================================================================\n')
                f.write('REM This file processes SMS notifications for verified payslips\n')
                f.write('REM ================================================================\n\n')

                f.write(f'echo Processing SMS batch: {os.path.basename(batch_file_path)}\n')
                f.write(f'echo.\n\n')

                # TODO: Add your SMS gateway command here
                # Example: call your SMS sending program
                # f.write('C:\\SMS\\sender.exe "%~dp0{os.path.basename(batch_file_path)}"\n\n')

                f.write('echo SMS batch queued successfully!\n')
                f.write('echo.\n')
                f.write('echo File: {}\n'.format(batch_file_path))
                f.write('echo.\n')
                f.write('pause\n')

            print(f"[SMS] BAT runner created: {bat_filename}")
            return bat_filename

        except Exception as e:
            print(f"[ERROR] Failed to create BAT runner: {e}")
            return None

    def get_scheduled_time(self) -> Optional[datetime]:
        """
        Determine if SMS should be scheduled for later.
        If current time is after 18:00, schedule for next day 07:00.

        Returns:
            datetime to schedule, or None for immediate sending
        """
        now = datetime.now()

        # If after 18:00, schedule for tomorrow 07:00
        if now.hour >= 18:
            tomorrow = now + timedelta(days=1)
            scheduled = tomorrow.replace(hour=7, minute=0, second=0, microsecond=0)
            print(f"[SMS] After 18:00 - scheduling for {scheduled.strftime('%Y-%m-%d %H:%M')}")
            return scheduled

        # Otherwise send immediately
        return None

    def send_sms(self, mobile: str, message: str, force_immediate: bool = False) -> Dict:
        """
        Send a single SMS message. If after 18:00, schedules for 07:00 next day.

        Args:
            mobile: Mobile number to send to
            message: SMS message content
            force_immediate: If True, sends immediately regardless of time

        Returns:
            Dict with 'success' and 'message' keys
        """
        if not mobile:
            return {'success': False, 'message': 'No mobile number provided'}

        messages = [{'mobile': mobile, 'message': message}]

        # Check if we should schedule
        scheduled_time = None if force_immediate else self.get_scheduled_time()

        batch_file = self.create_batch_file(messages, scheduled_time=scheduled_time)
        if batch_file:
            # Upload to WinSMS FTP
            success, result_msg = self.upload_to_winsms(batch_file)

            if scheduled_time and success:
                result_msg = f"SMS scheduled for {scheduled_time.strftime('%Y-%m-%d %H:%M')}"

            return {'success': success, 'message': result_msg}

        return {'success': False, 'message': 'Failed to create batch file'}

    def send_bulk_sms(self, messages: List[Dict[str, str]], force_immediate: bool = False) -> Dict:
        """
        Send multiple SMS messages. If after 18:00, schedules for 07:00 next day.

        Args:
            messages: List of dicts with 'mobile' and 'message' keys
            force_immediate: If True, sends immediately regardless of time

        Returns:
            Dict with 'success', 'message', and 'count' keys
        """
        if not messages:
            return {'success': False, 'message': 'No messages to send', 'count': 0}

        # Check if we should schedule
        scheduled_time = None if force_immediate else self.get_scheduled_time()

        batch_file = self.create_batch_file(messages, scheduled_time=scheduled_time)
        if batch_file:
            # Upload to WinSMS FTP
            success, result_msg = self.upload_to_winsms(batch_file)

            if scheduled_time and success:
                result_msg = f"SMS scheduled for {scheduled_time.strftime('%Y-%m-%d %H:%M')}"

            return {'success': success, 'message': result_msg, 'count': len(messages)}

        return {'success': False, 'message': 'Failed to create batch file', 'count': 0}

    def send_payslip_verification_sms(self, staff_name: str, mobile: str,
                                     start_date: str, end_date: str,
                                     gross_pay: float, deductions: float, net_pay: float,
                                     payment_method: str = "CASH",
                                     loan_balance: float = 0.0,
                                     loan_deduction: float = 0.0,
                                     savings_balance: float = 0.0) -> bool:
        """
        Send single SMS notification for verified payslip

        Args:
            staff_name: Name of staff member
            mobile: Mobile number
            start_date: Pay period start date
            end_date: Pay period end date
            gross_pay: Gross pay amount
            deductions: Total deductions
            net_pay: Net pay amount
            payment_method: "CASH" or bank account details
            loan_balance: Outstanding loan balance
            loan_deduction: Loan deduction for this period
            savings_balance: Current savings balance

        Returns:
            True if SMS queued successfully
        """
        # Build comprehensive payslip message
        message = (f"WAGEPRO Payslip {start_date}-{end_date}: "
                  f"GROSS R{gross_pay:.2f}, DEDUCT R{deductions:.2f}, "
                  f"NET R{net_pay:.2f}")

        # Add payment method
        message += f" | PAY: {payment_method}"

        # Add loan status if applicable
        if loan_deduction > 0:
            message += f" | LOAN: -R{loan_deduction:.2f}, BAL R{loan_balance:.2f}"
        elif loan_balance > 0:
            message += f" | LOAN BAL: R{loan_balance:.2f}"

        # Add savings balance if applicable
        if savings_balance > 0:
            message += f" | SAVINGS: R{savings_balance:.2f}"

        messages = [{
            'mobile': mobile,
            'message': message
        }]

        batch_file = self.create_batch_file(messages)
        if batch_file:
            bat_file = self.create_bat_runner(batch_file)
            return bat_file is not None

        return False

    def send_bulk_verification_sms(self, payslips: List[Dict]) -> Optional[str]:
        """
        Send bulk SMS notifications for multiple verified payslips

        Args:
            payslips: List of payslip dicts with staff info

        Returns:
            Path to BAT file if successful, None otherwise
        """
        messages = []

        for payslip in payslips:
            staff_name = payslip.get('staff_name', 'Staff')
            mobile = payslip.get('staff_mobile', '')
            period_info = payslip.get('period_info', 'current period')
            net_pay = payslip.get('net_pay', 0.0)

            if mobile:  # Only add if mobile number exists
                message = f"WAGEPRO: Your payslip for {period_info} has been verified. Net Pay: R{net_pay:.2f}. Thank you!"
                messages.append({
                    'mobile': mobile,
                    'message': message
                })

        if not messages:
            print("[SMS] No messages to send (no mobile numbers)")
            return None

        batch_file = self.create_batch_file(messages)
        if batch_file:
            return self.create_bat_runner(batch_file)

        return None


# Convenience function for easy import
def notify_payslip_verified(staff_name: str, mobile: str, period_info: str, net_pay: float) -> bool:
    """
    Quick function to send SMS notification

    Args:
        staff_name: Name of staff member
        mobile: Mobile number
        period_info: Pay period description
        net_pay: Net pay amount

    Returns:
        True if SMS queued successfully
    """
    notifier = SMSNotifier()
    return notifier.send_payslip_verification_sms(staff_name, mobile, period_info, net_pay)
