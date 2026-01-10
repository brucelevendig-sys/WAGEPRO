"""
Payroll Models for WAGEPRO
Handles 2-weekly pay periods, loans, deductions, and payslips
"""

from sqlalchemy import Column, Integer, String, Float, Date, DateTime, Boolean, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.database import Base


class PayPeriodStatus(str, enum.Enum):
    """Pay period status"""
    OPEN = "open"              # Currently active pay period
    PROCESSING = "processing"  # Being calculated
    APPROVED = "approved"      # Approved by manager
    PAID = "paid"             # Payments made
    CLOSED = "closed"         # Finalized and archived


class PayPeriod(Base):
    """
    2-weekly (fortnight) pay periods
    """
    __tablename__ = "pay_periods"

    id = Column(Integer, primary_key=True, index=True)

    # Period Details
    period_number = Column(Integer, nullable=False)
    year = Column(Integer, nullable=False, index=True)
    start_date = Column(Date, nullable=False, index=True)
    end_date = Column(Date, nullable=False, index=True)

    # Status
    status = Column(SQLEnum(PayPeriodStatus), default=PayPeriodStatus.OPEN, nullable=False, index=True)

    # Totals
    total_gross_pay = Column(Float, default=0.0)
    total_deductions = Column(Float, default=0.0)
    total_net_pay = Column(Float, default=0.0)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    approved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    paid_at = Column(DateTime, nullable=True)

    # Relationships
    approved_by = relationship("User", foreign_keys=[approved_by_id])
    payslips = relationship("Payslip", back_populates="pay_period", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<PayPeriod {self.year}-{self.period_number}: {self.start_date} to {self.end_date}>"


class Payslip(Base):
    """
    Individual staff payslip for a pay period
    Records all earnings, deductions, and days worked (fortnight)
    """
    __tablename__ = "payslips"

    id = Column(Integer, primary_key=True, index=True)

    # Links
    pay_period_id = Column(Integer, ForeignKey("pay_periods.id"), nullable=False, index=True)
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, index=True)

    # Days Worked - 2 Week Cycle (14 days)
    # Values: 0.0 = Not worked, 0.5 = Half day, 1.0 = Full day
    # Week 1
    w1_monday = Column(Float, default=0.0)
    w1_tuesday = Column(Float, default=0.0)
    w1_wednesday = Column(Float, default=0.0)
    w1_thursday = Column(Float, default=0.0)
    w1_friday = Column(Float, default=0.0)
    w1_saturday = Column(Float, default=0.0)
    w1_sunday = Column(Float, default=0.0)

    # Week 2
    w2_monday = Column(Float, default=0.0)
    w2_tuesday = Column(Float, default=0.0)
    w2_wednesday = Column(Float, default=0.0)
    w2_thursday = Column(Float, default=0.0)
    w2_friday = Column(Float, default=0.0)
    w2_saturday = Column(Float, default=0.0)
    w2_sunday = Column(Float, default=0.0)

    # Hours Breakdown
    total_hours = Column(Float, default=0.0)
    weekday_hours = Column(Float, default=0.0)
    weekend_hours = Column(Float, default=0.0)

    # Rates (snapshot from staff at time of creation)
    hourly_rate = Column(Float, nullable=True)
    daily_rate = Column(Float, nullable=True)

    # Earnings
    weekday_pay = Column(Float, default=0.0)
    weekend_pay = Column(Float, default=0.0)
    overtime_hours = Column(Float, default=0.0)
    overtime_pay = Column(Float, default=0.0)
    bonus = Column(Float, default=0.0)
    standby_allowance = Column(Float, default=0.0)  # Standby pay for no-work days
    gross_pay = Column(Float, default=0.0)

    # Deductions
    loan_deduction = Column(Float, default=0.0)
    other_deductions = Column(Float, default=0.0)
    total_deductions = Column(Float, default=0.0)

    # Rewards & Penalties (points converted to Rand)
    reward_points = Column(Integer, default=0)  # Total reward points for this period
    penalty_points = Column(Integer, default=0)  # Total penalty points for this period
    reward_adjustment = Column(Float, default=0.0)  # Rand value added to pay (positive)
    penalty_adjustment = Column(Float, default=0.0)  # Rand value deducted (positive value)

    # Final Amount
    net_pay = Column(Float, nullable=False)

    # Notes
    notes = Column(Text, nullable=True)

    # Payment Method
    payment_method = Column(String(10), default='BANK')  # 'BANK' or 'CASH'

    # Status
    is_verified = Column(Boolean, default=False)
    is_approved = Column(Boolean, default=False)
    is_paid = Column(Boolean, default=False)
    paid_at = Column(DateTime, nullable=True)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    pay_period = relationship("PayPeriod", back_populates="payslips")
    staff = relationship("StaffMember")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<Payslip {self.staff_id} - Period {self.pay_period_id}: R{self.net_pay}>"


class Loan(Base):
    """
    Staff loans deducted from payslips
    """
    __tablename__ = "loans"

    id = Column(Integer, primary_key=True, index=True)

    # Loan Details
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, index=True)
    description = Column(String(200), nullable=False)

    # Amounts
    total_amount = Column(Float, nullable=False)
    amount_paid = Column(Float, default=0.0)
    amount_remaining = Column(Float, nullable=False)
    installment_amount = Column(Float, nullable=False)
    total_installments = Column(Integer, nullable=True)  # Total number of installments

    # Dates
    loan_date = Column(Date, nullable=False)
    start_deduction_date = Column(Date, nullable=False)

    # Status
    is_active = Column(Boolean, default=True, index=True)
    is_completed = Column(Boolean, default=False)
    completed_at = Column(DateTime, nullable=True)

    # Notes
    notes = Column(Text, nullable=True)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    staff = relationship("StaffMember")
    created_by = relationship("User", foreign_keys=[created_by_id])

    @property
    def payment_progress_percentage(self):
        """Calculate payment progress"""
        if self.total_amount > 0:
            return (self.amount_paid / self.total_amount) * 100
        return 0

    def __repr__(self):
        return f"<Loan {self.staff_id}: R{self.amount_remaining} remaining>"


class LoanTransaction(Base):
    """
    Loan transaction history
    """
    __tablename__ = "loan_transactions"

    id = Column(Integer, primary_key=True, index=True)
    loan_id = Column(Integer, ForeignKey("loans.id"), nullable=False, index=True)
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, index=True)

    # Transaction details
    transaction_type = Column(String(20), nullable=False)  # 'disbursement' or 'repayment'
    amount = Column(Float, nullable=False)
    balance_before = Column(Float, nullable=False)
    balance_after = Column(Float, nullable=False)

    # References
    payslip_id = Column(Integer, ForeignKey("payslips.id"), nullable=True)

    # Description
    description = Column(Text, nullable=True)

    # Tracking
    transaction_date = Column(Date, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    loan = relationship("Loan")
    staff = relationship("StaffMember")
    payslip = relationship("Payslip")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<LoanTransaction {self.transaction_type}: R{self.amount}>"


class Deduction(Base):
    """
    Other deductions from payslips (medical aid, UIF, pension, etc.)
    """
    __tablename__ = "deductions"

    id = Column(Integer, primary_key=True, index=True)

    # Deduction Details
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, index=True)
    description = Column(String(200), nullable=False)
    deduction_type = Column(String(50), nullable=False)  # "fixed", "percentage", "once_off"

    # Amount Calculation
    percentage = Column(Float, nullable=True)  # If percentage-based
    fixed_amount = Column(Float, nullable=True)  # If fixed amount

    # Status
    is_active = Column(Boolean, default=True, index=True)
    start_date = Column(Date, nullable=True)
    end_date = Column(Date, nullable=True)

    # Notes
    notes = Column(Text, nullable=True)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    staff = relationship("StaffMember")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def calculate_deduction(self, gross_pay):
        """Calculate deduction amount based on type"""
        if self.deduction_type == "percentage" and self.percentage:
            return gross_pay * (self.percentage / 100)
        elif self.deduction_type in ["fixed", "once_off"] and self.fixed_amount:
            return self.fixed_amount
        return 0.0

    def __repr__(self):
        return f"<Deduction {self.description} for Staff {self.staff_id}>"


class SavingsAccount(Base):
    """
    Staff savings account
    Tracks total savings balance and transaction history
    """
    __tablename__ = "savings_accounts"

    id = Column(Integer, primary_key=True, index=True)
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, unique=True, index=True)

    # Balance
    total_balance = Column(Float, default=0.0, nullable=False)

    # Recurring savings amount (deducted each pay period)
    recurring_amount = Column(Float, default=0.0, nullable=False)

    # Status
    is_active = Column(Boolean, default=True, nullable=False)

    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Relationships
    staff = relationship("StaffMember")

    @property
    def available_for_loan(self):
        """Calculate how much can be borrowed (typically 80-90% of balance)"""
        return self.total_balance * 0.9  # 90% of savings can be borrowed

    def __repr__(self):
        return f"<SavingsAccount Staff {self.staff_id}: R{self.total_balance}>"


class SavingsTransaction(Base):
    """
    Individual savings transactions
    Records all deposits, withdrawals, and loan deductions
    """
    __tablename__ = "savings_transactions"

    id = Column(Integer, primary_key=True, index=True)
    savings_account_id = Column(Integer, ForeignKey("savings_accounts.id"), nullable=False, index=True)
    staff_id = Column(Integer, ForeignKey("staff_members.id"), nullable=False, index=True)

    # Transaction details
    transaction_type = Column(String(20), nullable=False)  # 'deposit', 'withdrawal', 'loan_deduction'
    amount = Column(Float, nullable=False)
    balance_after = Column(Float, nullable=False)

    # References
    payslip_id = Column(Integer, ForeignKey("payslips.id"), nullable=True)  # If from payslip deduction
    loan_id = Column(Integer, ForeignKey("loans.id"), nullable=True)  # If related to loan

    # Description
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    # Tracking
    transaction_date = Column(Date, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # Relationships
    savings_account = relationship("SavingsAccount")
    staff = relationship("StaffMember")
    payslip = relationship("Payslip")
    loan = relationship("Loan")
    created_by = relationship("User", foreign_keys=[created_by_id])

    def __repr__(self):
        return f"<SavingsTransaction {self.transaction_type}: R{self.amount}>"
