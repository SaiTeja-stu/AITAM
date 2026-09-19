import { useEffect, useState } from 'react';
import {
  GraduationCap,
  BookOpen,
  AlertOctagon,
  CheckCircle2,
  ShieldCheck,
  Search,
  Award,
  HelpCircle,
  Smartphone,
  QrCode,
  Globe,
  RefreshCw,
  Sparkles,
  XCircle,
  AlertTriangle,
  FileText,
  PhoneCall,
  ChevronRight,
  ShieldAlert,
} from 'lucide-react';
import { api } from '../api.js';
import { Spinner } from '../components/ui.jsx';

// Interactive Quiz Dataset
const QUIZ_QUESTIONS = [
  {
    id: 1,
    category: 'Payment Fraud',
    question: 'A buyer on an online marketplace sends you a QR code and says "Scan this QR code to receive your ₹5,000 payment". What happens if you scan it?',
    options: [
      { text: 'Money is deposited into your bank account immediately.', isCorrect: false },
      { text: 'Scanning or approving a QR code always DEDUCTS money from your account.', isCorrect: true },
      { text: 'It verifies your UPI ID without moving any funds.', isCorrect: false },
      { text: 'It creates a cash voucher in your wallet.', isCorrect: false },
    ],
    explanation: 'Remember: You NEVER scan a QR code or enter your UPI PIN to receive money. Scanning a QR code or entering a PIN always authorizes an outgoing payment.',
  },
  {
    id: 2,
    category: 'Phishing',
    question: 'You receive an urgent SMS: "Your SBI Account #4029 is blocked. Update KYC immediately at http://sbi-netbanking-update.in or card will be closed." What should you do?',
    options: [
      { text: 'Click the link right away to prevent your account from being blocked.', isCorrect: false },
      { text: 'Reply to the SMS asking if it is authentic.', isCorrect: false },
      { text: 'Delete the SMS, do not click the link, and check your status only via official bank channels.', isCorrect: true },
      { text: 'Forward the SMS to your friends to warn them.', isCorrect: false },
    ],
    explanation: 'Banks never send HTTP links in SMS asking for KYC verification. The link "sbi-netbanking-update.in" is a lookalike domain created by fraudsters.',
  },
  {
    id: 3,
    category: 'Credential Theft',
    question: 'A caller claiming to be from your bank security department says "Someone is trying to hack your account! I just sent an OTP to your phone, tell me the code to block the hacker!" What should you do?',
    options: [
      { text: 'Give them the OTP quickly so they can stop the hacker.', isCorrect: false },
      { text: 'Hang up immediately. No legitimate bank employee will EVER ask for your OTP.', isCorrect: true },
      { text: 'Ask for their employee ID before giving them the OTP.', isCorrect: false },
      { text: 'Ask them to text you their official office address first.', isCorrect: false },
    ],
    explanation: 'An OTP (One-Time Password) is the final line of defense for your account. Anyone asking for an OTP over the phone is committing fraud.',
  },
  {
    id: 4,
    category: 'Extortion',
    question: 'You receive a WhatsApp video call from a caller dressed in a police uniform claiming you are under "Digital Arrest" for a parcel containing illegal items, demanding money to clear your name. What is true?',
    options: [
      { text: 'Police and CBI regularly conduct legal arrests via WhatsApp video calls.', isCorrect: false },
      { text: 'You must pay the requested money as a "refundable security deposit".', isCorrect: false },
      { text: 'Law enforcement agencies NEVER arrest anyone over video call or demand money to clear cases.', isCorrect: true },
      { text: 'You should keep the video call going for 24 hours to prove innocence.', isCorrect: false },
    ],
    explanation: 'Digital Arrest is a total extortion scam. Law enforcement agencies never arrest anyone over video chat or request financial transfers to clear legal cases.',
  },
  {
    id: 5,
    category: 'Advance Fee Scam',
    question: 'You get a Telegram message promising ₹3,000 per day by simply liking YouTube videos, but you must first deposit a ₹1,000 "refundable task activation fee". What type of scam is this?',
    options: [
      { text: 'A legitimate freelance digital marketing job opportunity.', isCorrect: false },
      { text: 'An advance-fee task scam designed to steal your initial deposit and recruit you into money laundering.', isCorrect: true },
      { text: 'A government-sponsored work-from-home initiative.', isCorrect: false },
      { text: 'A standard recruitment procedure used by fortune 500 companies.', isCorrect: false },
    ],
    explanation: 'Legitimate employers never ask candidates to pay money or deposit funds to start working. Early small payouts are bait to lure you into depositing larger sums.',
  },
];

// Interactive Threat Scenarios Dataset
const SIMULATED_SCENARIOS = [
  {
    id: 'sms-phish',
    name: 'Phishing SMS Attack',
    type: 'SMS',
    icon: Smartphone,
    color: 'from-amber-500/20 to-red-500/20',
    borderColor: 'border-amber-500/40',
    content: 'URGENT: your HDFC Netbanking account has been suspended due to pending PAN update. Please update now at http://hdfc-pan-verify.tech to prevent permanent blocking.',
    redFlags: [
      'Sense of artificial urgency ("suspended", "permanent blocking")',
      'Unofficial domain name ("hdfc-pan-verify.tech" instead of "hdfcbank.com")',
      'Insecure HTTP protocol link',
      'Generic greeting without your actual account name',
    ],
    action: 'Do not click the link. Block the sender and report to 1930 cyber portal.',
  },
  {
    id: 'upi-qr',
    name: 'UPI "Receive Money" QR Scam',
    type: 'QR / Payment',
    icon: QrCode,
    color: 'from-cyan-500/20 to-blue-500/20',
    borderColor: 'border-cyan-500/40',
    content: 'upi://pay?pa=refunds-store99@okicici&pn=Refund%20Department&am=4999.00&cu=INR',
    redFlags: [
      'Scammer claims scanning this code will deposit ₹4,999 into your account',
      'The URI is a payment collect link ("upi://pay")',
      'Pressing Proceed or entering your PIN will IMMEDIATELY transfer ₹4,999 to the fraudster',
    ],
    action: 'Refuse the transaction. Remind the sender that receiving money NEVER requires entering a PIN or scanning a QR.',
  },
  {
    id: 'fake-portal',
    name: 'Lookalike Phishing Portal',
    type: 'Web Portal',
    icon: Globe,
    color: 'from-purple-500/20 to-indigo-500/20',
    borderColor: 'border-purple-500/40',
    content: 'https://www.paypa1-security-verification.com/login?token=89234',
    redFlags: [
      'Misspelled domain name: "paypa1" with a number 1 instead of letter "l"',
      'Extra subdomains ("security-verification.com")',
      'Single-page form requesting Password, Card Number, CVV, and OTP all at once',
    ],
    action: 'Always type the official domain manually into your browser address bar (e.g. paypal.com).',
  },
  {
    id: 'digital-extortion',
    name: 'Digital Arrest Extortion',
    type: 'Extortion',
    icon: ShieldAlert,
    color: 'from-red-500/20 to-pink-500/20',
    borderColor: 'border-red-500/40',
    content: 'Incoming Video Call: "CBI Cyber Cell Officer Investigation #882"',
    redFlags: [
      'Caller demands 24/7 camera surveillance and isolation',
      'Claims parcel #8921 contained illicit substances or illegal documents',
      'Asks for immediate money transfer to a "secret government audit account"',
    ],
    action: 'Disconnect the call immediately. Report the phone number to 1930 Cyber Helpline and your local police station.',
  },
];

export default function Education() {
  const [mods, setMods] = useState(null);
  const [err, setErr] = useState('');
  const [activeTab, setActiveTab] = useState('library'); // 'library' | 'quiz' | 'simulator' | 'checklist'
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  // Quiz state
  const [quizIndex, setQuizIndex] = useState(0);
  const [selectedOption, setSelectedOption] = useState(null);
  const [quizScore, setQuizScore] = useState(0);
  const [quizFinished, setQuizFinished] = useState(false);
  const [answersHistory, setAnswersHistory] = useState([]);

  // Simulator state
  const [activeScenarioId, setActiveScenarioId] = useState('sms-phish');

  useEffect(() => {
    api.education().then(setMods).catch((e) => setErr(e.message));
  }, []);

  if (err) {
    return (
      <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-5 text-sm text-red-400 flex items-center gap-3">
        <AlertOctagon className="h-5 w-5 shrink-0" />
        <span>Failed to load education modules: {err}</span>
      </div>
    );
  }

  if (!mods) {
    return (
      <div className="flex h-64 items-center justify-center gap-3 text-slate-400">
        <Spinner className="h-6 w-6 text-cyber-accent" />
        <span className="font-mono text-sm">Loading security awareness modules…</span>
      </div>
    );
  }

  // Filter modules
  const categories = ['ALL', ...new Set(mods.map((m) => m.category.toUpperCase()))];
  const filteredMods = mods.filter((m) => {
    const matchesCat = selectedCategory === 'ALL' || m.category.toUpperCase() === selectedCategory;
    const matchesSearch =
      m.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.summary.toLowerCase().includes(searchTerm.toLowerCase()) ||
      m.category.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const handleOptionSelect = (optIndex) => {
    if (selectedOption !== null) return; // Prevent changing answer
    setSelectedOption(optIndex);
    const q = QUIZ_QUESTIONS[quizIndex];
    const isCorrect = q.options[optIndex].isCorrect;
    if (isCorrect) setQuizScore((prev) => prev + 1);

    setAnswersHistory((prev) => [
      ...prev,
      {
        questionId: q.id,
        selectedOption: optIndex,
        isCorrect,
      },
    ]);
  };

  const handleNextQuiz = () => {
    if (quizIndex + 1 < QUIZ_QUESTIONS.length) {
      setQuizIndex((prev) => prev + 1);
      setSelectedOption(null);
    } else {
      setQuizFinished(true);
    }
  };

  const restartQuiz = () => {
    setQuizIndex(0);
    setSelectedOption(null);
    setQuizScore(0);
    setQuizFinished(false);
    setAnswersHistory([]);
  };

  const activeScenario = SIMULATED_SCENARIOS.find((s) => s.id === activeScenarioId) || SIMULATED_SCENARIOS[0];

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-3xl border border-cyber-border bg-gradient-to-r from-cyber-panel via-cyber-card to-cyber-dark p-6 md:p-8 shadow-2xl">
        <div className="absolute -right-10 -top-10 h-64 w-64 rounded-full bg-cyber-accent/10 blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2 max-w-2xl">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-1 text-xs font-mono font-semibold text-cyber-accent">
              <Sparkles className="h-3.5 w-3.5" /> SOC Cyber Awareness Hub
            </div>
            <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
              <GraduationCap className="h-8 w-8 text-cyber-accent" /> Security Awareness & Training Center
            </h1>
            <p className="text-xs md:text-sm text-slate-300 leading-relaxed">
              Interactive cyber threat mitigation guides, scam simulations, and awareness modules synchronized live via{' '}
              <code className="font-mono text-cyber-accent bg-cyber-dark/80 px-2 py-0.5 rounded border border-cyber-border">
                /api/v1/education/modules
              </code>.
            </p>
          </div>

          {/* Quick Metrics */}
          <div className="grid grid-cols-2 gap-3 shrink-0">
            <div className="rounded-2xl border border-cyber-border/80 bg-cyber-dark/80 p-3.5 text-center">
              <div className="text-xl font-bold font-mono text-white">{mods.length}</div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Awareness Modules</div>
            </div>
            <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-3.5 text-center">
              <div className="text-xl font-bold font-mono text-emerald-400">1930</div>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-300">National Helpline</div>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="mt-8 flex flex-wrap items-center gap-2 border-t border-cyber-border/60 pt-6">
          <button
            onClick={() => setActiveTab('library')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
              activeTab === 'library'
                ? 'bg-gradient-to-r from-cyber-accent to-cyber-indigo text-slate-950 shadow-cyber-glow'
                : 'bg-cyber-dark/80 text-slate-400 border border-cyber-border hover:text-white hover:bg-cyber-panel'
            }`}
          >
            <BookOpen className="h-4 w-4" /> Awareness Library ({mods.length})
          </button>

          <button
            onClick={() => setActiveTab('quiz')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
              activeTab === 'quiz'
                ? 'bg-gradient-to-r from-cyber-accent to-cyber-indigo text-slate-950 shadow-cyber-glow'
                : 'bg-cyber-dark/80 text-slate-400 border border-cyber-border hover:text-white hover:bg-cyber-panel'
            }`}
          >
            <Award className="h-4 w-4" /> Interactive Threat Quiz
          </button>

          <button
            onClick={() => setActiveTab('simulator')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
              activeTab === 'simulator'
                ? 'bg-gradient-to-r from-cyber-accent to-cyber-indigo text-slate-950 shadow-cyber-glow'
                : 'bg-cyber-dark/80 text-slate-400 border border-cyber-border hover:text-white hover:bg-cyber-panel'
            }`}
          >
            <AlertTriangle className="h-4 w-4" /> Threat Simulator
          </button>

          <button
            onClick={() => setActiveTab('checklist')}
            className={`flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-bold transition-all ${
              activeTab === 'checklist'
                ? 'bg-gradient-to-r from-cyber-accent to-cyber-indigo text-slate-950 shadow-cyber-glow'
                : 'bg-cyber-dark/80 text-slate-400 border border-cyber-border hover:text-white hover:bg-cyber-panel'
            }`}
          >
            <FileText className="h-4 w-4" /> Incident Checklist
          </button>
        </div>
      </div>

      {/* TAB 1: AWARENESS LIBRARY */}
      {activeTab === 'library' && (
        <div className="space-y-6">
          {/* Controls Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            {/* Search Input */}
            <div className="relative w-full sm:w-80">
              <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
              <input
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search modules, keywords, threats…"
                className="w-full rounded-xl border border-cyber-border bg-cyber-dark/90 pl-10 pr-4 py-2.5 text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-cyber-accent focus:ring-1 focus:ring-cyber-accent"
              />
            </div>

            {/* Category Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`rounded-lg px-3 py-1.5 text-[11px] font-bold font-mono transition-all uppercase ${
                    selectedCategory === cat
                      ? 'bg-cyber-accent text-slate-950 shadow-cyber-glow'
                      : 'bg-cyber-dark/80 text-slate-400 border border-cyber-border hover:text-white hover:bg-cyber-panel'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          {/* Module Cards Grid */}
          {filteredMods.length === 0 ? (
            <div className="rounded-2xl border border-cyber-border bg-cyber-panel/60 p-12 text-center text-slate-400">
              <BookOpen className="mx-auto h-8 w-8 text-slate-500 mb-2" />
              <p className="text-sm font-semibold">No modules match your search filter.</p>
              <button
                onClick={() => {
                  setSearchTerm('');
                  setSelectedCategory('ALL');
                }}
                className="mt-3 text-xs text-cyber-accent hover:underline"
              >
                Reset Search Filters
              </button>
            </div>
          ) : (
            <div className="grid gap-6 md:grid-cols-2">
              {filteredMods.map((m) => (
                <div
                  key={m.id}
                  className="glass-card rounded-2xl p-6 border border-cyber-border/80 flex flex-col justify-between space-y-5 transition-all hover:border-cyber-accent/40 hover:shadow-cyber-glow group"
                >
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <span className="rounded-lg border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-1 font-mono text-[11px] font-bold text-cyber-accent uppercase tracking-wider">
                        {m.category}
                      </span>
                      <span className="flex items-center gap-1 font-mono text-[11px] text-slate-400">
                        <BookOpen className="h-3.5 w-3.5 text-cyber-accent" /> #{m.id}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-lg font-bold text-white tracking-wide group-hover:text-cyber-accent transition-colors">
                        {m.title}
                      </h3>
                      <p className="mt-1.5 text-xs text-slate-300 leading-relaxed">{m.summary}</p>
                    </div>

                    {/* Key Defense Points */}
                    {m.keyPoints && m.keyPoints.length > 0 && (
                      <div className="rounded-xl border border-cyber-border/60 bg-cyber-dark/70 p-4 space-y-2.5">
                        <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                          <ShieldCheck className="h-4 w-4" /> Defense Best Practices
                        </div>
                        <ul className="space-y-2 text-xs text-slate-300">
                          {m.keyPoints.map((k, i) => (
                            <li key={i} className="flex items-start gap-2.5">
                              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400 mt-0.5" />
                              <span className="leading-snug">{k}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Threat Red Flags */}
                    {m.redFlags && m.redFlags.length > 0 && (
                      <div className="rounded-xl border border-red-500/25 bg-red-500/5 p-4 space-y-2.5">
                        <div className="flex items-center gap-2 text-xs font-bold text-red-400">
                          <AlertOctagon className="h-4 w-4" /> Threat Red Flags
                        </div>
                        <ul className="space-y-2 text-xs text-slate-300">
                          {m.redFlags.map((k, i) => (
                            <li key={i} className="flex items-start gap-2.5">
                              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-red-400 shadow-[0_0_6px_#f87171]" />
                              <span className="leading-snug">{k}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  <div className="pt-2 border-t border-cyber-border/40 flex items-center justify-between text-xs text-slate-400">
                    <span className="font-mono text-[11px]">Sync ID: {m.id}</span>
                    <button
                      onClick={() => {
                        setActiveTab('quiz');
                        restartQuiz();
                      }}
                      className="flex items-center gap-1 font-semibold text-cyber-accent hover:underline"
                    >
                      Test Quiz <ChevronRight className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: INTERACTIVE THREAT QUIZ */}
      {activeTab === 'quiz' && (
        <div className="max-w-3xl mx-auto space-y-6">
          {!quizFinished ? (
            <div className="glass-card rounded-3xl p-6 md:p-8 border border-cyber-border/80 space-y-6 shadow-2xl">
              {/* Quiz Header */}
              <div className="flex items-center justify-between border-b border-cyber-border/60 pb-4">
                <div>
                  <span className="rounded-lg border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-1 font-mono text-[11px] font-bold text-cyber-accent uppercase">
                    {QUIZ_QUESTIONS[quizIndex].category}
                  </span>
                  <h2 className="text-lg font-bold text-white mt-2">
                    Question {quizIndex + 1} of {QUIZ_QUESTIONS.length}
                  </h2>
                </div>
                <div className="flex items-center gap-2 rounded-xl border border-cyber-border bg-cyber-dark/80 px-4 py-2 font-mono text-sm text-cyber-accent">
                  <Award className="h-4 w-4 text-cyber-accent" /> Score: {quizScore} / {QUIZ_QUESTIONS.length}
                </div>
              </div>

              {/* Progress Bar */}
              <div className="h-2 w-full rounded-full bg-cyber-dark overflow-hidden border border-cyber-border/40">
                <div
                  className="h-full bg-gradient-to-r from-cyber-accent to-cyber-indigo transition-all duration-300"
                  style={{ width: `${((quizIndex + 1) / QUIZ_QUESTIONS.length) * 100}%` }}
                />
              </div>

              {/* Question Text */}
              <p className="text-base md:text-lg font-semibold text-slate-100 leading-relaxed">
                {QUIZ_QUESTIONS[quizIndex].question}
              </p>

              {/* Options */}
              <div className="space-y-3">
                {QUIZ_QUESTIONS[quizIndex].options.map((opt, i) => {
                  let btnStyle =
                    'border-cyber-border bg-cyber-dark/80 text-slate-300 hover:border-cyber-accent/60 hover:bg-cyber-panel';

                  if (selectedOption !== null) {
                    if (opt.isCorrect) {
                      btnStyle = 'border-emerald-500/60 bg-emerald-500/20 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.3)]';
                    } else if (selectedOption === i) {
                      btnStyle = 'border-red-500/60 bg-red-500/20 text-red-300 shadow-[0_0_12px_rgba(239,68,68,0.3)]';
                    } else {
                      btnStyle = 'border-cyber-border/40 bg-cyber-dark/40 text-slate-500 opacity-60';
                    }
                  }

                  return (
                    <button
                      key={i}
                      onClick={() => handleOptionSelect(i)}
                      disabled={selectedOption !== null}
                      className={`w-full text-left rounded-2xl border p-4 text-xs md:text-sm font-medium transition-all flex items-center justify-between gap-3 ${btnStyle}`}
                    >
                      <span>{opt.text}</span>
                      {selectedOption !== null && (
                        <div>
                          {opt.isCorrect ? (
                            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                          ) : selectedOption === i ? (
                            <XCircle className="h-5 w-5 text-red-400 shrink-0" />
                          ) : null}
                        </div>
                      )}
                    </button>
                  );
                })}
              </div>

              {/* Feedback Explanation */}
              {selectedOption !== null && (
                <div className="rounded-2xl border border-cyber-accent/30 bg-cyber-accent/10 p-4 text-xs text-cyber-accent space-y-1.5 animate-fadeIn">
                  <div className="flex items-center gap-2 font-bold uppercase tracking-wider text-[11px]">
                    <HelpCircle className="h-4 w-4" /> Explanation & Defense Protocol
                  </div>
                  <p className="text-slate-200 leading-relaxed">{QUIZ_QUESTIONS[quizIndex].explanation}</p>
                </div>
              )}

              {/* Next Question Button */}
              {selectedOption !== null && (
                <div className="flex justify-end pt-2">
                  <button
                    onClick={handleNextQuiz}
                    className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-accent to-cyber-indigo px-6 py-3 text-xs font-bold text-slate-950 shadow-cyber-glow hover:opacity-90 transition-all"
                  >
                    <span>{quizIndex + 1 === QUIZ_QUESTIONS.length ? 'View Quiz Results' : 'Next Question'}</span>
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              )}
            </div>
          ) : (
            /* Quiz Completed Screen */
            <div className="glass-card rounded-3xl p-8 border border-cyber-border/80 text-center space-y-6 shadow-2xl">
              <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-gradient-to-br from-cyber-accent to-cyber-indigo p-0.5 shadow-cyber-glow">
                <div className="flex h-full w-full items-center justify-center rounded-[22px] bg-cyber-dark">
                  <Award className="h-10 w-10 text-cyber-accent" />
                </div>
              </div>

              <div className="space-y-2">
                <h2 className="text-2xl font-bold text-white">Quiz Completed!</h2>
                <p className="text-sm text-slate-400">
                  You scored <span className="font-bold text-cyber-accent font-mono text-lg">{quizScore}</span> out of{' '}
                  <span className="font-bold text-white font-mono text-lg">{QUIZ_QUESTIONS.length}</span>
                </p>
              </div>

              <div className="rounded-2xl border border-cyber-border bg-cyber-dark/80 p-4 max-w-md mx-auto">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Status Badge</div>
                <div className="text-base font-bold text-emerald-400 flex items-center justify-center gap-2">
                  {quizScore === 5 ? (
                    <>
                      <Award className="h-5 w-5 text-amber-400" />
                      <span className="text-amber-400">Master SOC Threat Specialist</span>
                    </>
                  ) : quizScore >= 3 ? (
                    <>
                      <ShieldCheck className="h-5 w-5 text-emerald-400" />
                      <span>Certified Cyber Security Officer</span>
                    </>
                  ) : (
                    <>
                      <AlertOctagon className="h-5 w-5 text-amber-400" />
                      <span className="text-amber-400">Awareness Trainee (Review Modules)</span>
                    </>
                  )}
                </div>
              </div>

              <div className="flex justify-center gap-4">
                <button
                  onClick={restartQuiz}
                  className="flex items-center gap-2 rounded-xl border border-cyber-border bg-cyber-panel px-5 py-2.5 text-xs font-bold text-slate-200 hover:bg-cyber-dark transition-all"
                >
                  <RefreshCw className="h-4 w-4" /> Retake Quiz
                </button>
                <button
                  onClick={() => setActiveTab('library')}
                  className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-accent to-cyber-indigo px-5 py-2.5 text-xs font-bold text-slate-950 shadow-cyber-glow"
                >
                  Back to Library
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: THREAT SIMULATOR PLAYGROUND */}
      {activeTab === 'simulator' && (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Scenario Selector List */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Select Threat Scenario</h3>
            <div className="space-y-2.5">
              {SIMULATED_SCENARIOS.map((sc) => {
                const IconComp = sc.icon;
                const isActive = sc.id === activeScenario.id;
                return (
                  <button
                    key={sc.id}
                    onClick={() => setActiveScenarioId(sc.id)}
                    className={`w-full text-left rounded-2xl border p-4 transition-all flex items-center justify-between ${
                      isActive
                        ? `${sc.borderColor} bg-cyber-panel text-white shadow-cyber-glow`
                        : 'border-cyber-border/80 bg-cyber-dark/80 text-slate-400 hover:text-slate-200 hover:bg-cyber-panel/60'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-2.5 rounded-xl border border-cyber-border bg-cyber-dark ${sc.color}`}>
                        <IconComp className="h-5 w-5 text-cyber-accent" />
                      </div>
                      <div>
                        <div className="text-sm font-bold text-white">{sc.name}</div>
                        <div className="text-[11px] font-mono text-slate-400">{sc.type}</div>
                      </div>
                    </div>
                    <ChevronRight className={`h-4 w-4 ${isActive ? 'text-cyber-accent' : 'text-slate-600'}`} />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Interactive Threat Visualizer Panel */}
          <div className="lg:col-span-2 glass-card rounded-3xl p-6 md:p-8 border border-cyber-border/80 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-cyber-border/60 pb-4">
              <div>
                <span className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-[11px] font-bold text-red-400 uppercase tracking-wider">
                  Live Attack Simulation
                </span>
                <h2 className="text-xl font-bold text-white mt-2">{activeScenario.name}</h2>
              </div>
              <span className="rounded-full border border-cyber-accent/30 bg-cyber-accent/10 px-3 py-1 font-mono text-xs font-bold text-cyber-accent">
                {activeScenario.type}
              </span>
            </div>

            {/* Simulated Device Screen */}
            <div className="rounded-2xl border border-cyber-border bg-cyber-dark p-5 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-cyber-border/40 pb-2 text-[10px] text-slate-500">
                <span>SIMULATED PAYLOAD SCREEN</span>
                <span className="text-red-400 font-bold">● RISK SCORE: 95-100</span>
              </div>
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-200 leading-relaxed font-mono">
                {activeScenario.content}
              </div>
            </div>

            {/* Security Analysis Breakdown */}
            <div className="space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-2">
                <AlertOctagon className="h-4 w-4" /> Detected Security Red Flags
              </h4>
              <ul className="space-y-2 text-xs text-slate-300">
                {activeScenario.redFlags.map((flag, i) => (
                  <li key={i} className="flex items-start gap-2.5 rounded-xl border border-red-500/20 bg-red-500/5 p-3">
                    <span className="mt-1 h-2 w-2 shrink-0 rounded-full bg-red-400 shadow-[0_0_8px_#f87171]" />
                    <span>{flag}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Defense Directive */}
            <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/10 p-4 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-emerald-400">
                <ShieldCheck className="h-4 w-4" /> Recommended Countermeasure Action
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">{activeScenario.action}</p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: EMERGENCY INCIDENT RESPONSE CHECKLIST */}
      {activeTab === 'checklist' && (
        <div className="glass-card rounded-3xl p-6 md:p-8 border border-cyber-border/80 space-y-6 shadow-2xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border/60 pb-4">
            <div>
              <h2 className="text-xl font-bold text-white flex items-center gap-2.5">
                <PhoneCall className="h-6 w-6 text-emerald-400" /> Emergency Cyber Crime Incident Checklist
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                If an employee or family member has accidentally fallen for a cyber fraud, execute these steps immediately.
              </p>
            </div>
            <div className="rounded-xl border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 font-mono text-xs font-bold text-emerald-400">
              Helpline: 1930 (National Cyber Crime)
            </div>
          </div>

          {/* Action Checklist Grid */}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="rounded-2xl border border-cyber-border bg-cyber-dark/80 p-5 space-y-3">
              <div className="flex items-center gap-3 text-sm font-bold text-cyber-accent">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyber-accent/20 text-cyber-accent font-mono text-xs font-bold">
                  1
                </div>
                <span>Block Bank Cards & UPI Handles</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Immediately call your bank’s official toll-free helpline or use mobile banking to freeze UPI transactions and block compromised cards.
              </p>
            </div>

            <div className="rounded-2xl border border-cyber-border bg-cyber-dark/80 p-5 space-y-3">
              <div className="flex items-center gap-3 text-sm font-bold text-emerald-400">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold">
                  2
                </div>
                <span>Report to 1930 / CyberCrime.gov.in</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Dial national cyber crime toll-free number 1930 within the golden hour (first 2 hours) to freeze fraudulently transferred funds.
              </p>
            </div>

            <div className="rounded-2xl border border-cyber-border bg-cyber-dark/80 p-5 space-y-3">
              <div className="flex items-center gap-3 text-sm font-bold text-amber-400">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-amber-500/20 text-amber-400 font-mono text-xs font-bold">
                  3
                </div>
                <span>Revoke Device Permissions & Passwords</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Uninstall any remote access app installed during the call (e.g. AnyDesk, TeamViewer) and change passwords on a separate clean device.
              </p>
            </div>

            <div className="rounded-2xl border border-cyber-border bg-cyber-dark/80 p-5 space-y-3">
              <div className="flex items-center gap-3 text-sm font-bold text-purple-400">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-purple-500/20 text-purple-400 font-mono text-xs font-bold">
                  4
                </div>
                <span>Submit Threat Report in Cyber Shield</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Submit the scam URL or phone number to the Cyber Shield Threat Report console to add it to the community blocklist across all devices.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
