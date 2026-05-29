"""
generator.py - Cryptographically secure password generator.

Generates passwords that satisfy configurable policy requirements
using Python's ``secrets`` module (CSPRNG-backed) instead of
``random``, making output suitable for security-sensitive contexts.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------

@dataclass
class PasswordPolicy:
    """
    Configurable policy for password generation.

    Attributes
    ----------
    length:
        Total password length.  Must be ≥ the sum of all ``min_*`` values.
    min_uppercase:
        Minimum number of uppercase letters required.
    min_lowercase:
        Minimum number of lowercase letters required.
    min_digits:
        Minimum number of digits required.
    min_special:
        Minimum number of special characters required.
    exclude_ambiguous:
        When *True*, removes visually ambiguous characters
        (``0 O o 1 l I i``).
    allowed_special:
        Override the default set of special characters.
    """

    length:           int  = 16
    min_uppercase:    int  = 2
    min_lowercase:    int  = 2
    min_digits:       int  = 2
    min_special:      int  = 2
    exclude_ambiguous: bool = False
    allowed_special:  str  = "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Validation -----------------------------------------------------------
    def __post_init__(self) -> None:
        min_required = (
            self.min_uppercase + self.min_lowercase
            + self.min_digits + self.min_special
        )
        # PINs and digit-only policies skip the 8-char floor.
        is_digit_only = (
            self.min_uppercase == 0
            and self.min_lowercase == 0
            and self.min_special == 0
            and self.min_digits > 0
        )
        floor = min_required if is_digit_only else max(8, min_required)
        if self.length < floor:
            raise ValueError(
                f"length ({self.length}) must be ≥ {floor} "
                f"to satisfy all minimum character-class requirements."
            )


# ---------------------------------------------------------------------------
# Pre-built policy presets
# ---------------------------------------------------------------------------

POLICY_BASIC: PasswordPolicy = PasswordPolicy(
    length=12, min_uppercase=1, min_lowercase=1, min_digits=1, min_special=1
)

POLICY_STANDARD: PasswordPolicy = PasswordPolicy(
    length=16, min_uppercase=2, min_lowercase=2, min_digits=2, min_special=2
)

POLICY_HIGH_SECURITY: PasswordPolicy = PasswordPolicy(
    length=24, min_uppercase=3, min_lowercase=3, min_digits=3, min_special=3,
    exclude_ambiguous=True,
)

POLICY_PIN: PasswordPolicy = PasswordPolicy(
    length=6, min_uppercase=0, min_lowercase=0, min_digits=6, min_special=0,
    allowed_special="",       # no specials needed — validation skips empty pool
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_AMBIGUOUS = set("0Oo1lIi")


def _build_pool(policy: PasswordPolicy) -> str:
    """Assemble the full character pool honoring *policy*."""
    upper   = string.ascii_uppercase
    lower   = string.ascii_lowercase
    digits  = string.digits
    special = policy.allowed_special

    if policy.exclude_ambiguous:
        upper   = "".join(c for c in upper   if c not in _AMBIGUOUS)
        lower   = "".join(c for c in lower   if c not in _AMBIGUOUS)
        digits  = "".join(c for c in digits  if c not in _AMBIGUOUS)
        special = "".join(c for c in special if c not in _AMBIGUOUS)

    pool_parts: List[str] = []
    if policy.min_uppercase > 0 or policy.min_lowercase == 0:
        pool_parts.append(upper)
    if policy.min_lowercase > 0 or policy.min_uppercase == 0:
        pool_parts.append(lower)
    if policy.min_digits > 0:
        pool_parts.append(digits)
    if policy.min_special > 0 and special:
        pool_parts.append(special)

    # Fallback: if only digits are used (PIN), return just digits.
    if not pool_parts:
        pool_parts.append(digits)

    return "".join(pool_parts)


def _pick_guaranteed(policy: PasswordPolicy) -> List[str]:
    """Return the mandatory characters defined by *policy*."""
    upper   = string.ascii_uppercase
    lower   = string.ascii_lowercase
    digits  = string.digits
    special = policy.allowed_special

    if policy.exclude_ambiguous:
        upper   = "".join(c for c in upper   if c not in _AMBIGUOUS)
        lower   = "".join(c for c in lower   if c not in _AMBIGUOUS)
        digits  = "".join(c for c in digits  if c not in _AMBIGUOUS)
        special = "".join(c for c in special if c not in _AMBIGUOUS)

    mandatory: List[str] = []
    mandatory += [secrets.choice(upper)   for _ in range(policy.min_uppercase)]
    mandatory += [secrets.choice(lower)   for _ in range(policy.min_lowercase)]
    mandatory += [secrets.choice(digits)  for _ in range(policy.min_digits)]
    if policy.min_special > 0 and special:
        mandatory += [secrets.choice(special) for _ in range(policy.min_special)]
    return mandatory


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_password(policy: Optional[PasswordPolicy] = None) -> str:
    """
    Generate a single cryptographically secure password.

    Parameters
    ----------
    policy:
        A :class:`PasswordPolicy` instance.  Defaults to
        :data:`POLICY_STANDARD` when *None*.

    Returns
    -------
    str
        A password satisfying every constraint in *policy*.
    """
    if policy is None:
        policy = POLICY_STANDARD

    pool      = _build_pool(policy)
    mandatory = _pick_guaranteed(policy)
    remaining = policy.length - len(mandatory)

    password_chars = mandatory + [secrets.choice(pool) for _ in range(remaining)]

    # Cryptographically shuffle (Fisher–Yates via secrets.SystemRandom)
    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)

    return "".join(password_chars)


def generate_batch(
    count:  int = 5,
    policy: Optional[PasswordPolicy] = None,
) -> List[str]:
    """
    Generate *count* unique passwords using *policy*.

    Parameters
    ----------
    count:
        Number of passwords to generate (1–100).
    policy:
        Password policy; defaults to :data:`POLICY_STANDARD`.

    Returns
    -------
    List[str]
        A list of *count* distinct passwords.

    Raises
    ------
    ValueError
        If *count* is outside the range [1, 100].
    """
    if not (1 <= count <= 100):
        raise ValueError("count must be between 1 and 100.")

    seen: set[str] = set()
    results: List[str] = []

    while len(results) < count:
        pw = generate_password(policy)
        if pw not in seen:
            seen.add(pw)
            results.append(pw)

    return results


def generate_passphrase(
    word_count:  int = 4,
    separator:   str = "-",
    capitalize:  bool = True,
    append_digit: bool = True,
) -> str:
    """
    Generate a memorable passphrase from a built-in word list.

    The built-in list is a compact subset of the EFF large word list.
    For production use, supply a larger external word list.

    Parameters
    ----------
    word_count:
        Number of words (3–8).
    separator:
        Character(s) between words.
    capitalize:
        Capitalise the first letter of each word.
    append_digit:
        Append a random two-digit number for extra entropy.
    """
    if not (3 <= word_count <= 8):
        raise ValueError("word_count must be between 3 and 8.")

    # Compact EFF-inspired word subset (keep import-free)
    _WORDS = [
        "abbey","abbot","abide","able","abort","about","above","abrupt",
        "aside","asset","atlas","attic","audio","audit","autumn","avid",
        "bacon","badge","bagel","baker","ballot","bamboo","banner","barley",
        "basin","batch","beach","begin","below","bench","berry","birch",
        "bison","blade","blame","bland","blast","blend","bliss","block",
        "bloom","blunt","board","bonus","boost","booth","born","bound",
        "boxer","brace","brain","brave","bread","breed","brick","bride",
        "brief","brine","brisk","broad","broth","brown","brunch","brush",
        "buddy","build","built","bulky","bunch","cabin","cable","cadet",
        "camel","canal","candy","cargo","carol","carry","catch","cedar",
        "chalk","chart","chase","check","chess","chest","chief","child",
        "choir","chunk","civic","civil","claim","clamp","clash","clean",
        "clear","clerk","click","cliff","climb","cling","clock","clone",
        "close","cloth","cloud","clown","coach","coast","cobra","comet",
        "coral","crane","crisp","cross","crown","crush","cubic","cycle",
        "daily","dairy","dance","datum","debut","decay","decor","depot",
        "derby","digit","diner","disco","ditch","diver","dizzy","dodge",
        "dogma","drill","drink","drive","drone","drool","drops","drove",
        "drum","dusk","duvet","eagle","early","earth","eight","elite",
        "ember","empty","enjoy","enter","envoy","epoch","equal","essay",
        "ethos","event","evict","exact","exert","exile","extra","fable",
        "facet","fairy","faith","false","fancy","feast","feral","ferry",
        "fetch","fiber","field","fifth","fifty","finch","first","fixed",
        "fjord","flame","flash","flask","fleet","flesh","float","flood",
        "floor","flora","floss","flour","flute","focal","foggy","folio",
        "forge","forth","forum","frame","fresh","front","froze","fruit",
        "fully","fungi","funky","funnel","fuzzy","gamer","gauge","gavel",
        "gaze","gecko","genre","ghost","glade","glare","glass","gleam",
        "globe","gloss","glyph","gnome","golem","grace","grade","grain",
        "grand","grant","grasp","grass","gravel","great","green","greet",
        "grill","grind","groan","groin","grove","growl","gruel","guard",
        "guess","guest","guide","guile","gusto","habit","haiku","hardy",
        "harsh","haven","hazel","hedge","heist","helix","hello","herbs",
        "heron","hills","hints","hippo","hoist","holly","honor","horse",
        "hotel","house","human","humor","humus","hyena","ideal","image",
        "inbox","indie","infer","ingot","inner","input","intro","ivory",
        "jazzy","jelly","joust","judge","juice","jumbo","jumpy","kayak",
        "kebab","knack","kneel","knife","knoll","koala","kraft","label",
        "lance","large","laser","latch","later","layer","leafy","learn",
        "ledge","legal","lemon","level","light","lilac","linen","liner",
        "liver","local","lodge","logic","lolly","lotus","lucky","lunar",
        "lyric","magic","major","maker","maple","march","marsh","maxim",
        "mayor","media","melon","mercy","merit","metal","micro","minor",
        "minus","mirth","misty","model","moist","money","moose","mossy",
        "motor","motto","mount","mouse","mulch","music","myrrh","nadir",
        "naive","nerve","night","ninja","noble","noise","north","notch",
        "novel","nurse","nymph","ocean","offer","olive","onion","opera",
        "optic","orbit","organ","other","ounce","outer","oxide","ozone",
        "paint","panda","panel","panic","paper","pasta","patch","pause",
        "pearl","pedal","penny","petal","phase","pilot","pinch","pixie",
        "pixel","pizza","plaid","plain","plane","plant","plaza","pluck",
        "plumb","plume","plump","plunge","poker","polar","polka","porch",
        "power","press","pride","prism","prize","probe","proof","prose",
        "proto","prowl","prune","psalm","pulse","punch","pupil","purge",
        "pygmy","quail","qualm","quest","queue","quick","quiet","quota",
        "quote","radar","radio","rally","ranch","range","rapid","raven",
        "reach","realm","recap","reign","relay","relic","remix","repay",
        "resin","rider","ridge","right","risky","river","robot","rocky",
        "rogue","rouge","rough","round","royal","rugby","ruler","rural",
        "rusty","sadly","saint","salad","salon","salsa","salvo","sandy",
        "sauce","sauna","scale","scene","scout","screw","serum","seven",
        "shade","shaft","shale","shark","sharp","sheen","sheet","shelf",
        "shell","shift","shine","shire","shirt","short","shout","shown",
        "siege","sigma","silly","since","sixth","sixty","skill","skull",
        "slate","slave","sleek","sleet","slept","slice","slide","slope",
        "sloth","slugs","smart","smell","smile","smoke","snack","snake",
        "solve","sonic","south","spark","spawn","speed","spend","spice",
        "spine","spiral","spite","split","spoon","sport","spray","spree",
        "sprig","squad","squid","stack","staff","stage","stain","stake",
        "stale","stand","stark","start","stash","steal","steam","steel",
        "steep","steer","stern","stone","stood","storm","story","stout",
        "stove","strap","straw","strip","strut","study","stump","sugar",
        "super","surge","swamp","swarm","sweep","sweet","swept","swift",
        "swing","swipe","swirl","swoop","sword","synth","tabby","table",
        "taffy","talon","tangy","tapir","taunt","taxis","teach","tepid",
        "terse","their","these","thick","thorn","those","three","throw",
        "thrum","thumb","tiara","tiger","tiled","timer","tired","titan",
        "today","token","topaz","topic","total","tough","tower","trace",
        "track","trade","trail","train","tramp","trawl","treat","tribe",
        "trick","troop","trove","truce","trunk","trust","truth","tulip",
        "tuner","tuple","tweak","twice","ultra","under","unify","unity",
        "until","upper","urban","usage","usher","utmost","valid","valor",
        "value","vapor","vault","velvet","venom","viola","viral","vista",
        "vivid","vocal","voice","voter","voter","wagon","waltz","watch",
        "water","weave","wedge","weird","wheat","where","which","while",
        "whole","whose","widen","width","windy","witch","witty","woman",
        "world","wrath","write","yacht","zebra","zesty","zilch","zonal",
    ]

    words = [secrets.choice(_WORDS) for _ in range(word_count)]
    if capitalize:
        words = [w.capitalize() for w in words]

    phrase = separator.join(words)
    if append_digit:
        phrase += separator + str(secrets.randbelow(90) + 10)

    return phrase