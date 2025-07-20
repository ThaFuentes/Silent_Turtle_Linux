#password.py
#!/usr/bin/env python3
# password.py — Priority-driven password generator with injected lists support (2025-07-18)

import itertools
import re
import string
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence

def _load_wordlist(filename: str) -> List[str]:
    p = Path(filename)
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return []

def _load_area_codes_from_file(filename: str = "area_codes.txt") -> List[str]:
    p = Path(filename)
    if p.exists():
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return []

def _month_numbers(zero_pad: bool = True) -> List[str]:
    return [f"{m:02d}" if zero_pad else str(m) for m in range(1, 13)] + [str(m) for m in range(1, 13)]

def _month_abbrs() -> List[str]:
    caps = [datetime(2000, m, 1).strftime("%b") for m in range(1, 13)]
    return caps + [m.lower() for m in caps]

def _month_full() -> List[str]:
    caps = [datetime(2000, m, 1).strftime("%B") for m in range(1, 13)]
    return caps + [m.lower() for m in caps]

def _days() -> List[str]:
    return [f"{d:02d}" for d in range(1, 32)] + [str(d) for d in range(1, 32)]

def _years(start: int = 1970) -> Sequence[str]:
    now = datetime.now().year
    full = [str(y) for y in range(start, now + 1)]
    short = [y[-2:] for y in full]
    return full + short

def _digits_tokens(min_len: int = 1, max_len: int = 4) -> List[str]:
    tokens: List[str] = []
    for l in range(min_len, max_len + 1):
        tokens.extend(str(n) for n in range(10**(l - 1), 10**l))
    return tokens

def _valid_prefixes() -> Iterable[str]:
    for prefix in range(200, 1000):
        p = f"{prefix:03d}"
        if p[0] == p[1] == p[2]:
            continue
        if (int(p[0]) + 1 == int(p[1]) and int(p[1]) + 1 == int(p[2])):
            continue
        if (int(p[0]) - 1 == int(p[1]) and int(p[1]) - 1 == int(p[2])):
            continue
        yield p

class PasswordGenerator:
    """Streams exhaustive, priority-ordered password chunks for WPA cracking."""

    SYMBOLS: Sequence[str] = ['!', '@', '#', '$', '%', '&', '*', '_', '-', '.', '?']

    def __init__(
        self,
        *,
        chunk_size: int = 500_000,
        check_stop: Optional[Callable[[], bool]] = None,
        area_codes: Optional[List[str]] = None,
        generator_order: Optional[List[str]] = None,
        names_file: str = "names.txt",
        adjs_file: str = "adjectives.txt",
        nouns_file: str = "nouns.txt",
        names: Optional[List[str]] = None,
        adjectives: Optional[List[str]] = None,
        nouns: Optional[List[str]] = None,
        digits_min: int = 1,
        digits_max: int = 4,
        min_len: int = 8,
        max_len: int = 63,
        static_text: Optional[List[str]] = None
    ):
        # Load or override wordlists
        self.names = names if names is not None else _load_wordlist(names_file)
        self.adjs = adjectives if adjectives is not None else _load_wordlist(adjs_file)
        self.nouns = nouns if nouns is not None else _load_wordlist(nouns_file)
        self.static = static_text or []

        # Date & digit tokens
        self.month_nums = _month_numbers()
        self.month_abbr = _month_abbrs()
        self.month_full = _month_full()
        self.days = _days()
        self.years = list(_years())
        self.digits_tok = _digits_tokens(digits_min, digits_max)

        # Area codes
        if area_codes:
            self.area_codes = [ac for ac in area_codes if re.fullmatch(r"\d{3}", ac)]
        else:
            self.area_codes = _load_area_codes_from_file()

        # Core settings
        self.chunk_size = max(1, chunk_size)
        self._should_stop = check_stop or (lambda: False)
        self.min_len = min_len
        self.max_len = max_len

        # Generator order
        self.generator_order = generator_order or [
            "gen_phone_numbers",
            "gen_name_month_day",
            "gen_name_month_day_sym",
            "gen_single_name",
            "gen_single_adj",
            "gen_single_noun",
            "gen_two_word_permutations",
            "gen_three_word_permutations",
            "gen_name_month_day_year",
            "gen_word_year_sym",
            "gen_two_words_year_sym",
            "gen_three_words_year_sym",
            "gen_word_digits_sym",
            "gen_two_words_digits_sym",
            "gen_three_words_digits_sym",
            "gen_name_static_digits_sym",
            "gen_random_insert",
            "gen_word_phone_sym",
            "gen_phone_year_sym",
            "gen_letter_phone_letter_sym",
        ]

        self.letters = list(string.ascii_letters)

    def _in_len(self, pw: str) -> bool:
        return self.min_len <= len(pw) <= self.max_len

    def gen_phone_numbers(self) -> Iterable[str]:
        prefixes = list(_valid_prefixes())
        for ac in self.area_codes:
            for pfx in prefixes:
                for ln in range(10_000):
                    pw = f"{ac}{pfx}{ln:04d}"
                    if self._in_len(pw):
                        yield pw

    def gen_name_month_day(self) -> Iterable[str]:
        for name in self.names:
            for mon in itertools.chain(self.month_nums, self.month_abbr, self.month_full):
                for day in self.days:
                    pw = f"{name}{mon}{day}"
                    if self._in_len(pw):
                        yield pw

    def gen_name_month_day_sym(self) -> Iterable[str]:
        for name in self.names:
            for mon in itertools.chain(self.month_nums, self.month_abbr, self.month_full):
                for day in self.days:
                    for sym in [''] + self.SYMBOLS:
                        pw = f"{name}{mon}{day}{sym}"
                        if self._in_len(pw):
                            yield pw

    def gen_single_name(self) -> Iterable[str]:
        for w in self.names:
            if self._in_len(w):
                yield w

    def gen_single_adj(self) -> Iterable[str]:
        for w in self.adjs:
            if self._in_len(w):
                yield w

    def gen_single_noun(self) -> Iterable[str]:
        for w in self.nouns:
            if self._in_len(w):
                yield w

    def gen_two_word_permutations(self) -> Iterable[str]:
        pools = [(self.names, self.adjs), (self.names, self.nouns), (self.adjs, self.nouns)]
        for a, b in pools:
            for w1 in a:
                for w2 in b:
                    for combo in (f"{w1}{w2}", f"{w2}{w1}"):
                        if self._in_len(combo):
                            yield combo

    def gen_three_word_permutations(self) -> Iterable[str]:
        all_words = self.names + self.adjs + self.nouns
        for perm in itertools.permutations(all_words, 3):
            pw = "".join(perm)
            if self._in_len(pw):
                yield pw

    def gen_name_month_day_year(self) -> Iterable[str]:
        for name in self.names:
            for mon in itertools.chain(self.month_nums, self.month_abbr, self.month_full):
                for day in self.days:
                    for yr in self.years:
                        for sym in [''] + self.SYMBOLS:
                            pw = f"{name}{mon}{day}{yr}{sym}"
                            if self._in_len(pw):
                                yield pw

    def gen_word_year_sym(self) -> Iterable[str]:
        for w in itertools.chain(self.names, self.adjs, self.nouns):
            for yr in self.years:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{w}{yr}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_two_words_year_sym(self) -> Iterable[str]:
        for combo in self.gen_two_word_permutations():
            for yr in self.years:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{combo}{yr}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_three_words_year_sym(self) -> Iterable[str]:
        for combo in self.gen_three_word_permutations():
            for yr in self.years:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{combo}{yr}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_word_digits_sym(self) -> Iterable[str]:
        for w in itertools.chain(self.names, self.adjs, self.nouns):
            for d in self.digits_tok:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{w}{d}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_two_words_digits_sym(self) -> Iterable[str]:
        for combo in self.gen_two_word_permutations():
            for d in self.digits_tok:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{combo}{d}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_three_words_digits_sym(self) -> Iterable[str]:
        for combo in self.gen_three_word_permutations():
            for d in self.digits_tok:
                for sym in [''] + self.SYMBOLS:
                    pw = f"{combo}{d}{sym}"
                    if self._in_len(pw):
                        yield pw

    def gen_name_static_digits_sym(self) -> Iterable[str]:
        if not self.static:
            return
        for name in self.names:
            for st in self.static:
                for d in self.digits_tok:
                    for sym in [''] + self.SYMBOLS:
                        pw = f"{name}{st}{d}{sym}"
                        if self._in_len(pw):
                            yield pw

    def gen_random_insert(self) -> Iterable[str]:
        for w in itertools.chain(self.names, self.adjs, self.nouns):
            for d in self.digits_tok:
                for sym in [''] + self.SYMBOLS:
                    for combo in (f"{d}{w}{sym}", f"{w}{d}{sym}", f"{d}{sym}{w}", f"{w}{sym}{d}"):
                        if self._in_len(combo):
                            yield combo

    def gen_word_phone_sym(self) -> Iterable[str]:
        prefixes = list(_valid_prefixes())
        for ac in self.area_codes:
            for pfx in prefixes:
                for ln in range(10_000):
                    phone = f"{ac}{pfx}{ln:04d}"
                    for w in itertools.chain(self.names, self.adjs, self.nouns):
                        for sym in [''] + self.SYMBOLS:
                            pw1 = f"{w}{phone}{sym}"
                            if self._in_len(pw1):
                                yield pw1
                            pw2 = f"{phone}{w}{sym}"
                            if self._in_len(pw2):
                                yield pw2

    def gen_phone_year_sym(self) -> Iterable[str]:
        prefixes = list(_valid_prefixes())
        for ac in self.area_codes:
            for pfx in prefixes:
                for ln in range(10_000):
                    phone = f"{ac}{pfx}{ln:04d}"
                    for yr in self.years:
                        for sym in [''] + self.SYMBOLS:
                            pw = f"{phone}{yr}{sym}"
                            if self._in_len(pw):
                                yield pw

    def gen_letter_phone_letter_sym(self) -> Iterable[str]:
        prefixes = list(_valid_prefixes())
        for ac in self.area_codes:
            for pfx in prefixes:
                for ln in range(10_000):
                    base = f"{ac}{pfx}{ln:04d}"
                    if not self._in_len(base):
                        continue
                    for l1 in self.letters:
                        for l2 in self.letters:
                            for sym in self.SYMBOLS:
                                pw = f"{l1}{base}{l2}{sym}"
                                if self._in_len(pw):
                                    yield pw

    def chunked_passwords(self) -> Iterable[List[str]]:
        buffer: List[str] = []
        check_every = 10_000
        steps = 0

        for meth in self.generator_order:
            gen_fn = getattr(self, meth)
            for pw in gen_fn():
                buffer.append(pw)
                steps += 1
                if len(buffer) >= self.chunk_size:
                    yield buffer
                    buffer = []
                if steps >= check_every:
                    steps = 0
                    if self._should_stop():
                        if buffer:
                            yield buffer
                        return
            if buffer:
                yield buffer
                buffer = []

    def __iter__(self) -> Iterable[List[str]]:
        return self.chunked_passwords()
