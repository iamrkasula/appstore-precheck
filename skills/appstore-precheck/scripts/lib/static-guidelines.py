#!/usr/bin/env python3
"""Narrow, advisory source/manifest/metadata checks; never shipping proof."""
import argparse
import fnmatch
import json
import os
import pathlib
import plistlib
import re
import stat
from xml.parsers.expat import ExpatError

PRUNE = {'.git', 'Pods', 'Carthage', '.build', 'build', 'DerivedData',
         'SourcePackages', 'checkouts', '.swiftpm', '.claude', 'worktrees',
         'node_modules', 'vendor', '.planning', '.symlinks', '*.app', '*.xcarchive', '*.dSYM', '*.xcframework'}
SOURCE = {'.swift', '.m', '.mm', '.h', '.js', '.jsx', '.ts', '.tsx'}
RESOURCE = {'.strings', '.xcstrings'}
ADS = (r'GoogleMobileAds|GADMobileAds|AppLovinSDK|ALSdk|AppsFlyerLib|\bAdjust\b|'
       r'FBAudienceNetwork|BranchSDK|IronSource|UnityAds|VungleAds|Chartboost|'
       r'InMobi|IMSdk|MTGSDK|PAGAdSDK|BUAdSDK|\bSingular\b|KochavaTracker|TenjinSDK')
TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)


def uncomment(text):
    return TOKEN.sub(lambda m: '\n' * m[0].count('\n') if m[0].startswith(('/', '/*')) else m[0], text)


def checked_bytes(path):
    limit = (8 if path.suffix in RESOURCE else 2) * 1024 * 1024
    fd = os.open(str(path), os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('special file skipped')
        if info.st_size > limit:
            raise ValueError('input exceeds read limit')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('input exceeds read limit')
    return data


def checked_text(path):
    data = checked_bytes(path)
    encoding = 'utf-16' if path.suffix == '.strings' and data[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8'
    return data.decode(encoding)


def input_error(path, exc, root=None):
    path = pathlib.Path(path)
    try:
        name = str(path.relative_to(root)) if root else path.name
    except ValueError:
        name = path.name
    return name + (' (special file skipped)' if isinstance(exc, ValueError) and str(exc) == 'special file skipped' else '')


def read_candidate(path):
    if path.suffix in {'.plist', '.entitlements'}:
        value = plistlib.loads(checked_bytes(path))
        if not isinstance(value, dict):
            raise ValueError('manifest root is not a dictionary')
        return plistlib.dumps(value).decode('utf-8')
    return checked_text(path)


def read_files(root, excludes):
    result, gaps = {}, []
    onerror = lambda exc: gaps.append(input_error(exc.filename, exc, root))
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        keep = [d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in PRUNE | set(excludes))]
        for d in keep:
            if (pathlib.Path(folder) / d).is_symlink():
                gaps.append(input_error(pathlib.Path(folder) / d, ValueError('symlink'), root))
        dirs[:] = [d for d in keep if not (pathlib.Path(folder) / d).is_symlink()]
        for name in files:
            path = pathlib.Path(folder) / name
            if path.suffix not in SOURCE | RESOURCE | {'.plist', '.entitlements', '.pbxproj', '.xcscheme', '.xcconfig'} and name not in {'Podfile', 'Package.swift', 'Package.resolved'}:
                continue
            try:
                result[path] = read_candidate(path)
            except (OSError, UnicodeError, ValueError, plistlib.InvalidFileException, ExpatError) as exc:
                gaps.append(input_error(path, exc, root))
    return result, gaps


def context(root, metadata, main, excludes, portfolio=()):
    files, gaps = read_files(root, excludes)
    src = {p: uncomment(t) for p, t in files.items() if p.suffix in SOURCE}
    resources = {p: t for p, t in files.items() if p.suffix in RESOURCE}
    plists = {p: plistlib.loads(t.encode('utf-8')) for p, t in files.items()
              if p.suffix in {'.plist', '.entitlements'}}
    main_data = plists.get(main, {})
    if main not in plists and main.exists():
        try:
            main_data = plistlib.loads(read_candidate(main).encode('utf-8'))
        except (OSError, UnicodeError, ValueError, plistlib.InvalidFileException, ExpatError) as exc:
            gaps.append(input_error(main, exc, root))
    extensions = {p: v for p, v in plists.items() if 'NSExtension' in v or 'NSAppClip' in v}
    return dict(root=root, metadata=metadata, main=main_data, files=files, gaps=gaps,
                src=src, resources=resources, plists=plists, extensions=extensions,
                portfolio=list(portfolio))


def outcome(hit=False, reason='', path=None, skip=False):
    return dict(status='SKIP' if skip else 'WARN' if hit else 'PASS',
                reason=reason or 'No matching risk signal in scanned inputs.',
                file=str(path) if path else '')


def hit_file(files, pattern):
    return next((p for p, text in files.items() if re.search(pattern, text, re.I)), None)


def metadata_files(c, names):
    base = c['metadata']
    if not base.is_dir() or base.is_symlink():
        return []
    files = [p for locale in sorted(base.iterdir()) if locale.is_dir() and not locale.is_symlink()
             and locale.name not in {'default', 'review_information', 'trade_representative_contact_information'}
             for name in names for p in [locale / (name + '.txt')] if p.is_file() or p.is_symlink()]
    for p in files:
        try:
            checked_text(p)
        except (OSError, UnicodeError, ValueError) as exc:
            detail = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            err = ValueError(input_error(p, exc, c.get('root')) + ': ' + detail)
            err.filename = None
            err.sanitized = True
            raise err from exc
    return files


def app_version(c):
    version = str(c['main'].get('CFBundleShortVersionString', ''))
    if re.fullmatch(r'\d+(?:\.\d+){1,2}', version):
        return version
    versions = {v for p, text in c['files'].items() if p.suffix == '.pbxproj'
                for v in re.findall(r'\bMARKETING_VERSION\s*=\s*"?(\d+(?:\.\d+){1,2})"?\s*;', uncomment(text))}
    if versions:
        return next(iter(versions)) if len(versions) == 1 else ''
    version_file = c['metadata'] / 'version.txt'
    return checked_text(version_file).strip() if version_file.is_file() else ''


def release_notes(c):
    files = metadata_files(c, ['release_notes'])
    if not files:
        return outcome(skip=True, reason='Release notes metadata unavailable.')
    version, initial_empty = app_version(c), False
    for p in files:
        value = checked_text(p).strip()
        desc = p.with_name('description.txt')
        same = desc.is_file() and not desc.is_symlink() and value == checked_text(desc).strip()
        if not value and version in ('1.0', '1.0.0'):
            initial_empty = True
            continue
        if not value and not version:
            return outcome(True, 'Empty release notes with unknown version; low-confidence update review.', p)
        if not value or re.fullmatch(r'lorem(?: ipsum)?[.!]?|TODO|N[/-]A', value, re.I) or same:
            return outcome(True, 'Release notes are empty, a placeholder, or repeat the description.', p)
    if initial_empty:
        return outcome(reason='empty release notes accepted for the initial version')
    return outcome(reason='Release notes contain specific non-placeholder text.')


def restart(c):
    source = {p: t for p, t in c['src'].items()
              if not re.search(r'(?m)^\s*(?:@testable\s+)?import\s+(?:Testing|XCTest)\b', t)}
    p = hit_file(source, r'"[^"\n]{0,512}(?:restart your device|reboot|change your settings in Settings\s*>\s*General)[^"\n]{0,512}"')
    p = p or hit_file(c['resources'], r'restart your device|\breboot\b|change your settings in Settings\s*>\s*General')
    return outcome(bool(p), 'Device restart/settings instruction string; inspect the user-facing context.' if p else '', p)


def browser(c):
    deps = {p: uncomment(t) for p, t in c['files'].items() if p.name in {'Podfile', 'Package.swift', 'Package.resolved'} or p.suffix == '.pbxproj'}
    p = next((p for p, text in deps.items()
              if re.search(r"[\"'][^\"'\n]{0,512}\b(?:Chromium|CEF|Gecko|Blink)\b(?![^\"'\n]{0,512}\.(?:swift|m|mm|h|storyboard|xib)[\"'])|\b(?:Chromium|CEF|Gecko|Blink)\.framework", text)), None)
    legacy = hit_file(c['src'], r'\bUIWebView\s*(?:\(|[*>])|:\s*UIWebView\b')
    if legacy:
        return outcome(True, 'Deprecated UIWebView reference; verify the shipping target and Xcode SDK before removal.', legacy)
    return outcome(bool(p), 'Non-WebKit engine dependency signal; verify entitlement and regional eligibility.' if p else '', p)


def intents(c):
    declared = any(v.get('INIntentsSupported') or
                   re.search(r'intent', json.dumps(v.get('NSExtension', {})), re.I) for v in c['plists'].values())
    handler = hit_file(c['src'], r'\b(?:INExtension|INIntentHandlerProviding|\w+IntentHandling)\b|func\s+handler\s*\(\s*for\s+intent')
    modern = hit_file(c['src'], r':\s*(?:\w+\s*,\s*)?(?:AppIntent|AppShortcutsProvider)\b')
    bad = (declared and not (handler or modern)) or (handler and not declared)
    return outcome(bool(bad), 'Intent declaration/legacy handler mismatch; inspect target membership. AppIntent discovery needs no legacy plist.' if bad else 'No intent parity mismatch (or intents not used).', handler)


def call_filter(c):
    p = hit_file(c['src'], r'\b(?:ILMessageFilterExtension|CXCallDirectoryProvider|CXCallDirectoryManager)\b')
    ui = hit_file(c['src'], r'"[^"\n]{0,512}(?:blocked (?:numbers|callers)|call blocking|spam filter|blocking settings)[^"\n]{0,512}"') or hit_file(c['resources'], r'blocked numbers|call blocking|spam filter')
    return outcome(bool(p and not ui), 'Call/filter API signal without a visible blocking-control label; inspect reachable settings.' if p and not ui else 'No missing filter-control signal (or APIs not used).', p)


def face_auth(c):
    native = hit_file(c['src'], r'\b(?:LocalAuthentication|LAContext)\b')
    for p, text in c['src'].items():
        face = re.search(r'\b(?:VNFaceObservation|VNDetectFace\w*|FaceTecSDK|FacePhi)\b', text)
        auth = re.search(r'login|authenticate|authentication|identity verification', text, re.I)
        if face and auth and not native:
            return outcome(True, 'Face recognition and authentication context coexist without LocalAuthentication; inspect authentication design.', p)
    return outcome(reason='No custom face-authentication signal (or native authentication present).')


def documents(c):
    picker = hit_file(c['src'], r'\bUIDocumentPicker\w*\b|\.fileImporter\s*\(|\bUIDocumentBrowserViewController\b')
    if picker:
        return outcome(reason='System document access is used; inspect custom browser reachability separately.')
    title = hit_file(c['src'], r'(?:navigationTitle|Text|title\s*=)\s*\(?\s*"(?:My Files|Files|Documents)"')
    title = title or hit_file(c['resources'], r'"(?:My Files|Files|Documents)"')
    custom = next((p for p, t in c['src'].items()
                   if title and re.search(r'FileManager\.default\.contentsOfDirectory|\benumerator\s*\(\s*at\s*:', t)
                   and re.search(r'\b(?:List|Table|UICollectionView|UITableView)\b', t)), None)
    return outcome(bool(custom), 'Custom file-browser signal without system document access; inspect Files/iCloud availability.' if custom else 'No custom file-browser signal.', custom)


def extension_parity(c):
    if not c['extensions']:
        return outcome(reason='No discoverable extension target.')
    main_id = c['main'].get('CFBundleIdentifier', '')
    if not main_id or '$(' in main_id or '${' in main_id:
        return outcome(skip=True, reason='Main bundle identifier is absent or build-setting-derived; archive verification required.')
    for p, value in c['extensions'].items():
        bid = value.get('CFBundleIdentifier', '')
        if not bid or '$(' in bid or '${' in bid:
            return outcome(skip=True, reason='Extension bundle id resolved by build settings; archive verification required.', path=p)
        if not bid or not bid.startswith(main_id + '.'):
            return outcome(True, 'Extension bundle identifier is missing or lacks the main-app prefix; verify target configuration.', p)
    return outcome(reason='Literal extension bundle identifiers share the main-app prefix.')


def matter(c):
    p = hit_file(c['src'], r'\bimport\s+(?:MatterSupport|Matter)\b')
    entitlement = any('com.apple.developer.matter.allow-setup-payload' in v for v in c['plists'].values())
    supported = any(re.search('matter', json.dumps(v.get('NSExtension', {})), re.I) for v in c['extensions'].values())
    return outcome(bool((p or entitlement) and not supported), 'Matter setup signal without a discoverable MatterSupport extension; verify target configuration.' if (p or entitlement) and not supported else 'No missing Matter extension signal (or Matter not used).', p)


def extension_ads(c):
    if not c['extensions']:
        return outcome(skip=True, reason='No discoverable extension target; not applicable.')
    for plist in c['extensions']:
        if plist.parent == c['root'] or plist.parent.name in {'ios', 'Sources', 'src'}:
            return outcome(skip=True, reason='Extension source dir unresolved; inspect target membership.', path=plist)
        files = {p: t for p, t in c['src'].items() if plist.parent in p.parents}
        p = hit_file(files, r'(?:import\s+|@import\s+|#import\s*[<"])(?:' + ADS + r')\b')
        if p:
            return outcome(True, 'Advertising/attribution SDK imported by extension-directory source; verify extension target membership.', p)
    return outcome(reason='No advertising import in discovered extension directories; resolved link phases are not audited.')


def ar_depth(c):
    p = hit_file(c['src'], r'\bimport\s+ARKit\b') or hit_file(c['files'], r'ARKit\.framework')
    if not p:
        return outcome(reason='ARKit not used.')
    sessions = [f for f, t in c['src'].items() if re.search(r'\b(?:ARSession|ARView|RealityKit)\b', t)]
    screens = sum(len(re.findall(r'struct\s+\w+\s*:\s*View\b|class\s+\w+\s*:\s*UIViewController\b', t)) for t in c['src'].values())
    bad = len(sessions) == 1 and screens < 2
    return outcome(bad, 'AR use is confined to one source file with fewer than two view declarations; low-confidence depth review, not proof of inadequate AR.' if bad else 'No narrow AR-depth signal.', p)


def companion(c):
    p = hit_file(c['src'], r'"[^"\n]{0,512}(?:download|install)[ \t]{1,60}[^"\n]{1,60}[ \t]{1,60}to (?:continue|proceed|use)[^"\n]{0,512}"') or hit_file(c['resources'], r'(?:download|install)[ \t]{1,60}[^"\n]{1,60}[ \t]{1,60}to (?:continue|proceed|use)')
    bad = bool(c['main'].get('LSApplicationQueriesSchemes') and p)
    return outcome(bad, 'App-query schemes coexist with an install-to-continue instruction; inspect whether core functionality requires another app.' if bad else '', p if bad else None)


def game_ids(c):
    for p, text in c['src'].items():
        if re.search(r'\bGameKit\b', text) and re.search(r'\b(?:playerID|gamePlayerID|teamPlayerID)\b', text) and re.search(r'\b(?:URLRequest|URLSession|Analytics\.logEvent|Mixpanel|Amplitude)\b', text):
            return outcome(True, 'Game Center identifier and network/analytics code coexist in one file; trace actual data flow before concluding sharing.', p)
    return outcome(reason='No co-located Game Center identifier/network signal (or GameKit not used).')


def emoji(c):
    if not c['root'].is_dir():
        return outcome(skip=True, reason='Asset root is unavailable.')
    seen = 0
    for folder, dirs, files in os.walk(c['root'], followlinks=False):
        seen += len(files)
        dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, pattern) for pattern in PRUNE)
                   and not (pathlib.Path(folder) / d).is_symlink()]
        for name in dirs + files:
            p = pathlib.Path(folder) / name
            suspect = (name.lower().endswith('.imageset') and 'emoji' in name.lower())
            suspect = suspect or name.lower() == 'applecoloremoji.ttc'
            suspect = suspect or bool(re.search(r'(?:^|[_ -])(?:applecoloremoji|emoji)(?:[_ -]|\.)', name, re.I) and p.suffix.lower() == '.png')
            if suspect:
                return outcome(True, 'Possible embedded Apple emoji artwork by asset name; low-confidence visual/license review required.', p)
    if seen == 0:
        return outcome(skip=True, reason='No project files were read; emoji artwork assets not audited.')
    return outcome(reason='Apple emoji artwork asset signal not used.')


def miniapp(c):
    for p, text in c['src'].items():
        terms = [r'\bWKScriptMessageHandler\b', r'https?://[^"\s]{1,2048}(?:\.js\b|/scripts?/)', r'\bevaluateJavaScript\b', r'\b(?:CLLocationManager|AVCaptureSession|CNContactStore|requestWhenInUseAuthorization)\b']
        if all(re.search(term, text) for term in terms):
            return outcome(True, 'Remote JavaScript, message handler, evaluation and native-sensitive API coexist; inspect mini-app bridge exposure.', p)
    return outcome(reason='No combined remote-script/native-sensitive bridge signal (or webview not used).')


def endorsements(c):
    files = metadata_files(c, ['name', 'subtitle', 'description', 'keywords', 'promotional_text', 'release_notes'])
    if not files:
        return outcome(skip=True, reason='Store metadata unavailable.')
    for p in files:
        if re.search(r'Apple recommends|featured by Apple|Apple.s choice|Apple Design Award|#1 on the App Store|(?:official|endorsed by|approved by)\s+(?:Apple|App Store)', checked_text(p), re.I):
            return outcome(True, 'Apple endorsement/official-product marketing claim; verify authorization and accuracy.', p)
    return outcome(reason='No matched Apple endorsement claim in metadata.')


# §72 — 2.5.19 hidden / dormant / undocumented features (October 16, 2026 guideline).
# Four narrow signal families, any one of which is a WARN: a review-detection or
# hide-for-review identifier (source or remote-config key), a build-flag branch named
# after the App Store / review build, a date-gated unlock, and obfuscation tooling.
# Store-review prompts (SKStoreReviewController, requestReview, reviewPrompt) and
# product/order review vocabulary are deliberately outside every pattern.
REVIEW_GATE_KEYS = re.compile(
    r'(?<![A-Za-z0-9])(?:isAppStoreReview|isAppReview|appStoreReview|appReviewMode|reviewMode|isReviewMode|'
    r'inReviewMode|isUnderReview|underReview|isReviewing|isReviewBuild|reviewBuild|reviewerMode|'
    r'hideForReview|hiddenForReview|hide_for_review|hidden_for_review|review_mode|is_under_review|'
    r'under_review|appstore_review|app_review_mode|is_review_build)(?![A-Za-z0-9])', re.I)
REVIEW_GATE_FLAG = re.compile(r'#if\s+!?\s*(?:APPSTORE|APP_STORE|APPSTORE_BUILD|APPSTORE_REVIEW|APP_REVIEW|REVIEW_BUILD|UNDER_REVIEW)\b')
REVIEW_GATE_DATE = re.compile(
    r'(?:Date\(\)|Date\.now|\.timeIntervalSince1970)\s*[<>]=?\s*[A-Za-z_.]*(?:unlock|launch|golive|go_live|activation|enable|reveal|hidden|feature)[A-Za-z_.]*|'
    r'[A-Za-z_.]*(?:unlock|launch|golive|go_live|activation|enable|reveal|hidden|feature)[A-Za-z_.]*\s*[<>]=?\s*(?:Date\(\)|Date\.now)', re.I)
REVIEW_GATE_OBFUSCATION = re.compile(r'SwiftShield|swift-?obfuscator|iXGuard|Guardsquare|Arxan|Verimatrix|Promon|obfuscat', re.I)


def review_gate(c):
    signals = [(REVIEW_GATE_KEYS, 'review-detection or hide-for-review identifier'),
               (REVIEW_GATE_FLAG, 'App Store / review build-flag branch'),
               (REVIEW_GATE_DATE, 'date-gated feature unlock')]
    for pattern, kind in signals:
        p = next((p for p, text in c['src'].items() if pattern.search(text)), None)
        if p:
            return outcome(True, 'Hidden-feature gate signal (' + kind + '): 2.5.19 forbids hidden, dormant or undocumented features; verify the branch only drops debug tooling and that every shipped feature is visible to App Review.', p)
    deps = {p: uncomment(t) for p, t in c['files'].items() if p.name in {'Podfile', 'Package.swift', 'Package.resolved'} or p.suffix == '.pbxproj'}
    p = hit_file(deps, REVIEW_GATE_OBFUSCATION.pattern) or hit_file(c['src'], r'\b(?:SwiftShield|ObfuscatedString|StringObfuscator|Obfuscator)\b|import\s+\w*Obfuscat\w*')
    if p:
        return outcome(True, 'Code/string obfuscation tooling signal: 2.5.19 treats obfuscation used to hide undocumented features as grounds for removal and account termination; confirm nothing reviewable is concealed.', p)
    return outcome(reason='No review-mode gate, App Store build-flag branch, date-gated unlock or obfuscation tooling signal.')


# --- §73–§81: checks contributed from app-store-doctor -------------------------------
# All advisory (WARN/PASS), never FAIL; each states what it could not establish.

def release_source(c):
    """Source with debug-only code removed: `#if DEBUG` branches (keeping a `#else`
    branch, which is the release side) and SwiftUI preview code (from the first
    `#Preview` / `PreviewProvider` declaration to end of file, where previews live by
    convention). Release-risk checks read this so debug tooling is not reported."""
    out = {}
    for p, text in c['src'].items():
        if re.search(r'(?m)^\s*(?:@testable\s+)?import\s+(?:Testing|XCTest)\b', text):
            continue
        kept, stack = [], []
        for line in text.split('\n'):
            s = line.strip()
            if re.match(r'#if\b', s):
                pos = bool(re.search(r'\bDEBUG\b', s)) and not re.search(r'!\s*DEBUG\b', s)
                stack.append({'active': pos, 'neg': bool(re.search(r'!\s*DEBUG\b', s))})
            elif re.match(r'#(?:elseif|elif)\b', s) and stack:
                stack[-1]['active'] = bool(re.search(r'\bDEBUG\b', s)) and not re.search(r'!\s*DEBUG\b', s)
            elif re.match(r'#else\b', s) and stack:
                stack[-1]['active'] = stack[-1]['neg']
            elif re.match(r'#endif\b', s) and stack:
                stack.pop()
            if re.match(r'#Preview\b', s) or re.search(r':\s*PreviewProvider\b', s):
                break
            kept.append('' if any(level['active'] for level in stack) else line)
        out[p] = '\n'.join(kept)
    return out


def _settings_blocks(text):
    """(configuration name, buildSettings text) for every XCBuildConfiguration in a pbxproj."""
    for chunk in text.split('isa = XCBuildConfiguration;')[1:]:
        chunk = chunk.split('isa = ', 1)[0]
        name = re.search(r'\bname\s*=\s*"?([^";]+)"?\s*;', chunk)
        yield (name.group(1) if name else ''), chunk


def _fingerprint(files, root):
    """(file/type names, string literals, asset names, dependency ids) for one repo."""
    names, lits, deps = set(), set(), set()
    for p, text in files.items():
        if p.suffix in SOURCE:
            names.add(p.name.lower())
            names.update('type:' + t.lower() for t in re.findall(r'\b(?:struct|class|enum|protocol|actor)\s+(\w+)', text))
            lits.update(s.lower() for s in re.findall(r'"([^"\\\n]{7,120})"', text))
        elif p.name in {'Podfile', 'Package.swift', 'Package.resolved'}:
            deps.update(d.lower() for d in re.findall(r'"identity"\s*:\s*"([^"]+)"|pod\s+[\'"]([^\'"]+)', text) for d in d if d)
    assets = set()
    for folder, dirs, _ in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if not any(fnmatch.fnmatch(d, x) for x in PRUNE)]
        assets.update(d.lower() for d in dirs if d.endswith(('.imageset', '.colorset', '.appiconset')))
    return names, lits, assets, deps

def _jaccard(a, b):
    return len(a & b) / len(a | b) if a | b else 0.0


def portfolio(c):
    """§73 — 4.3(a): near-identical apps from one developer. Opt-in: compares this repo
    with the sibling app repos passed via --portfolio. Similarity is a weighted Jaccard of
    source file/type names, user-facing string literals, asset names and dependencies."""
    others = c.get('portfolio') or []
    if not others:
        return dict(status='OFF', reason='', file='')

    mine = _fingerprint(c['files'], c['root'])
    best = (0.0, None, ())
    for other in others:
        other = pathlib.Path(other)
        if not other.is_dir() or other.resolve() == c['root']:
            continue
        files, _ = read_files(other, [])
        theirs = _fingerprint(files, other)
        parts = tuple(_jaccard(a, b) for a, b in zip(mine, theirs))
        # A dimension empty on both sides (e.g. no dependencies anywhere) says nothing
        # about similarity, so it is left out and the remaining weights renormalized.
        weights = [w for w, a, b in zip((0.35, 0.35, 0.15, 0.15), mine, theirs) if a | b]
        used = [j for j, a, b in zip(parts, mine, theirs) if a | b]
        score = sum(w * j for w, j in zip(weights, used)) / sum(weights) if weights else 0.0
        shown = tuple(j if a | b else None for j, a, b in zip(parts, mine, theirs))
        if score > best[0] or best[1] is None:
            best = (score, other, shown)
    if best[1] is None:
        return outcome(skip=True, reason='No readable --portfolio directory to compare.')
    score, other, parts = best
    detail = '%s overall %.2f (%s)' % (other.name, score, ', '.join(
        '%s %s' % (label, 'n/a' if j is None else '%.2f' % j) for label, j in zip(('names', 'strings', 'assets', 'deps'), parts)))
    if score >= 0.6:
        return outcome(True, 'Near-identical sibling app: ' + detail + '. 4.3(a) asks for one app instead of many Bundle IDs of the same app; merge the variants or document real functional differences in the review notes. Shared infrastructure is normal; shared product is the risk.', None)
    return outcome(reason='Most similar --portfolio app: ' + detail + ' (below the 0.60 near-duplicate threshold).')


def release_config(c):
    """§74 — 2.2: the archived build is a debug build. Scheme ArchiveAction set to Debug,
    DEBUG in a Release configuration's compilation conditions, or Release built -Onone."""
    for p, text in c['files'].items():
        if p.suffix == '.xcscheme':
            m = re.search(r'<ArchiveAction[^>]*buildConfiguration\s*=\s*"([^"]+)"', text)
            if m and 'debug' in m.group(1).lower():
                return outcome(True, 'Scheme archives with the "%s" configuration: the submitted build would be a debug build (debug-only code, -Onone, development behaviour). Set ArchiveAction to Release.' % m.group(1), p)
    for p, text in c['files'].items():
        if p.suffix != '.pbxproj':
            continue
        for name, settings in _settings_blocks(text):
            if name.lower() not in ('release', 'appstore', 'production', 'prod'):
                continue
            cond = ' '.join(re.findall(r'(?:SWIFT_ACTIVE_COMPILATION_CONDITIONS|GCC_PREPROCESSOR_DEFINITIONS|OTHER_SWIFT_FLAGS)\s*=\s*(\([^)]*\)|"[^"]*"|[^;]+);', settings))
            if re.search(r'(?<![\w$])DEBUG(?![\w])', cond):
                return outcome(True, 'DEBUG compilation condition in the %s configuration: #if DEBUG code (mocks, debug menus, verbose logging) ships to App Review. Remove DEBUG from the release configuration.' % name, p)
            if re.search(r'SWIFT_OPTIMIZATION_LEVEL\s*=\s*"?-Onone"?\s*;', settings):
                return outcome(True, '%s configuration is built with -Onone: unoptimized code is slower at launch (watchdog risk) and usually means a debug configuration is being archived.' % name, p)
    return outcome(reason='Scheme archive configurations and Release build settings look like release builds.')


SECRET_PATTERNS = (
    ('Anthropic API key', r'\bsk-ant-[A-Za-z0-9_\-]{20,}'),
    ('OpenAI API key', r'\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,}'),
    ('AWS access key', r'\bAKIA[0-9A-Z]{16}\b'),
    ('Stripe live secret key', r'\b(?:sk|rk)_live_[A-Za-z0-9]{16,}'),
    ('GitHub token', r'\bgh[pousr]_[A-Za-z0-9]{30,}\b'),
    ('Slack token', r'\bxox[abprs]-[A-Za-z0-9\-]{10,}'),
    ('private key', r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
    ('Supabase service_role key', r'service_role[^\n]{0,80}eyJ[A-Za-z0-9_\-]{10,}|eyJ[A-Za-z0-9_\-]{10,}[^\n]{0,80}service_role'),
)


def secrets(c):
    """§75 — 1.6: a server-side credential embedded in code or a bundled plist ships in
    the binary, where anyone can extract it. Public client keys (Firebase, RevenueCat
    public, Supabase anon, Sentry DSN) are deliberately not matched. The value is
    never echoed: only its kind and a 4-character prefix."""
    files = dict(release_source(c))
    files.update({p: t for p, t in c['files'].items() if p.suffix in {'.plist', '.xcconfig'}})
    for p, text in files.items():
        for kind, pattern in SECRET_PATTERNS:
            m = re.search(pattern, text)
            if m:
                return outcome(True, 'Embedded %s (%s****): server credentials in the app bundle can be extracted and abused. Rotate it, move the call behind your own backend, and purge it from git history.' % (kind, m.group(0)[:4]), p)
    return outcome(reason='No server-side credential pattern in release source, plists or xcconfig files.')


FORMAT = re.compile(r'%(?:\d+\$)?[-+#0]*\d*(?:\.\d+)?(?:hh|h|ll|l|q|z|t|j|L)?[@dDuUxXoOfeEgGcCsSpaAi]|%%')


def _specs(value, subs=None):
    found = ['%' + (subs or {}).get(name, '?').replace('i', 'd') for name in re.findall(r'%(?:\d+\$)?#@(\w+)@', value)]
    value = re.sub(r'%(?:\d+\$)?#@\w+@', '', value)
    for spec in FORMAT.findall(value):
        if spec != '%%':
            found.append(re.sub(r'^%(\d+\$)?[-+#0]*\d*(\.\d+)?', '%', spec).replace('%i', '%d'))
    return sorted(found)


def _strings_pairs(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return dict(re.findall(r'"((?:\\.|[^"\\])*)"\s*=\s*"((?:\\.|[^"\\])*)"\s*;', text))


def localization_format(c):
    """§76 — 2.1: a translation whose format specifiers differ from the source (%@ vs
    %lld, a dropped argument) crashes or prints garbage at runtime. Positional reordering
    (%2$@ … %1$@) and String Catalog substitutions (%#@count@) are understood; plural and
    device variations are not compared (they legitimately drop arguments)."""
    for p, text in c['resources'].items():
        if p.suffix != '.xcstrings':
            continue
        try:
            catalog = json.loads(text)
        except ValueError:
            return outcome(True, 'String Catalog is not valid JSON; strings fall back to keys.', p)
        src = catalog.get('sourceLanguage', 'en')
        for key, entry in sorted((catalog.get('strings') or {}).items()):
            entry = entry or {}
            if entry.get('shouldTranslate') is False:
                continue
            locs = entry.get('localizations') or {}
            unit = locs.get(src) or {}
            if 'variations' in unit:
                continue
            subs = {k: (v or {}).get('formatSpecifier', '?') for k, v in (unit.get('substitutions') or {}).items()}
            want = _specs((unit.get('stringUnit') or {}).get('value', key), subs)
            for lang, loc in sorted(locs.items()):
                if lang == src or 'variations' in (loc or {}) or 'stringUnit' not in (loc or {}):
                    continue
                tsubs = {k: (v or {}).get('formatSpecifier', '?') for k, v in ((loc or {}).get('substitutions') or {}).items()}
                got = _specs(loc['stringUnit'].get('value', ''), tsubs)
                if '%?' not in want + got and got != want:
                    return outcome(True, 'Format specifiers differ in %s for key "%s" (%s: %s, source: %s); a mismatched argument crashes or renders the wrong value.' % (lang, key[:60], lang, ' '.join(got) or 'none', ' '.join(want) or 'none'), p)
    tables = {}
    for p, text in c['resources'].items():
        m = re.search(r'([^/]+)\.lproj$', p.parent.name + '') if p.suffix == '.strings' else None
        if m:
            tables.setdefault((p.parent.parent, p.name), {})[m.group(1)] = (p, _strings_pairs(text))
    for (_, name), langs in sorted(tables.items(), key=lambda x: str(x[0])):
        base = langs.get('en') or langs.get('Base')
        if not base:
            continue
        for lang, (p, pairs) in sorted(langs.items()):
            for key, value in pairs.items():
                if key in base[1] and _specs(value) != _specs(base[1][key]):
                    return outcome(True, 'Format specifiers differ in %s/%s for key "%s"; a mismatched argument crashes or renders the wrong value.' % (lang, name, key[:60]), p)
    return outcome(reason='Translated format specifiers match their source strings.')


def permission_localization(c):
    """§77 — 5.1.1: in a localized app, the permission purpose strings (Info.plist
    NS*UsageDescription) must be localized too (InfoPlist.xcstrings or
    <lang>.lproj/InfoPlist.strings), or users see the reason in the development language."""
    keys = {k for k in c['main'] if k.endswith('UsageDescription')}
    for p, text in c['files'].items():
        if p.suffix == '.pbxproj':
            keys.update(re.findall(r'INFOPLIST_KEY_(NS\w+UsageDescription)\s*=', text))
    langs, covered = set(), {}
    for p, text in c['resources'].items():
        if p.suffix == '.xcstrings':
            try:
                catalog = json.loads(text)
            except ValueError:
                continue
            for entry in (catalog.get('strings') or {}).values():
                langs.update((entry or {}).get('localizations', {}).keys())
            if p.name == 'InfoPlist.xcstrings':
                for key, entry in (catalog.get('strings') or {}).items():
                    for lang in (entry or {}).get('localizations', {}):
                        covered.setdefault(lang, set()).add(key)
        m = re.fullmatch(r'(.+)\.lproj', p.parent.name)
        if m and m.group(1) != 'Base':
            langs.add(m.group(1))
            if p.name == 'InfoPlist.strings':
                covered.setdefault(m.group(1), set()).update(_strings_pairs(text))
    langs = {l for l in langs if not l.startswith('en') and l != 'Base'}
    if not keys or not langs:
        return outcome(reason='No purpose strings, or the app is not localized beyond English.')
    missing = sorted(l for l in langs if keys - covered.get(l, set()))
    if missing:
        return outcome(True, 'Permission purpose strings are not localized for: %s (keys: %s). Add InfoPlist.xcstrings or <lang>.lproj/InfoPlist.strings entries.' % (', '.join(missing[:8]), ', '.join(sorted(keys)[:4])), None)
    return outcome(reason='Every purpose string is localized in every app language.')


def transaction_listener(c):
    """§78 — 3.1.1: StoreKit 2 purchases without a Transaction.updates listener miss
    renewals, refunds, Ask to Buy approvals and offer-code redemptions made outside the
    purchase call, so paying users can lose access. Subscription SDKs that listen for
    you (RevenueCat, Adapty, Qonversion, Apphud, Glassfy) are treated as listeners."""
    src = release_source(c)
    p = hit_file(src, r'\bProduct\.products\s*\(\s*for\s*:|\.purchase\s*\(\s*(?:options\s*:|\))')
    if not p or not hit_file(src, r'\bimport\s+StoreKit\b'):
        return outcome(reason='No StoreKit 2 purchase flow (or StoreKit not used).')
    if hit_file(src, r'\bTransaction\.updates\b|\bPurchases\.(?:shared|configure)\b|\bAdapty\.|\bQonversion\.|\bApphud\.|\bGlassfy\.'):
        return outcome(reason='StoreKit 2 purchases with a transaction-updates listener (or a subscription SDK).')
    return outcome(True, 'StoreKit 2 purchase flow without a Transaction.updates listener: start one at launch and finish() each verified transaction, or renewals, refunds and Ask to Buy approvals are missed.', p)


def bonjour(c):
    """§79 — 2.1: Bonjour browsing fails (NoAuth -65555) on iOS 14+ unless every browsed
    service type is declared in NSBonjourServices, so local-network discovery silently
    finds nothing in front of the reviewer."""
    p = hit_file(release_source(c), r'\bNWBrowser\b|\bNetServiceBrowser\b|\bDNSServiceBrowse\b|\bMCNearbyServiceBrowser\b')
    if not p:
        return outcome(reason='No Bonjour browsing API used.')
    declared = any('NSBonjourServices' in v for v in c['plists'].values()) or bool(
        hit_file({q: t for q, t in c['files'].items() if q.suffix == '.pbxproj'}, r'INFOPLIST_KEY_NSBonjourServices'))
    if declared:
        return outcome(reason='Bonjour browsing with NSBonjourServices declared.')
    return outcome(True, 'Bonjour browsing without NSBonjourServices: on iOS 14+ discovery fails unless every service type (e.g. _myapp._tcp) is declared, so the feature appears broken during review.', p)


ENTITLEMENT_USE = {
    'com.apple.developer.healthkit': r'\bHKHealthStore\b',
    'com.apple.developer.homekit': r'\bHMHomeManager\b',
    'com.apple.developer.networking.networkextension': r'\bNE[A-Z]\w*(?:Manager|Provider)\b',
    'com.apple.developer.networking.vpn.api': r'\bNEVPNManager\b|\bNETunnelProviderManager\b',
    'com.apple.developer.nfc.readersession.formats': r'\bNFC\w*ReaderSession\b',
    'com.apple.developer.in-app-payments': r'\bPKPaymentRequest\b|\bPKPaymentAuthorization|PayWithApplePayButton',
    'com.apple.developer.networking.wifi-info': r'CNCopyCurrentNetworkInfo|NEHotspotNetwork\.fetchCurrent',
    'com.apple.developer.family-controls': r'\bAuthorizationCenter\b|\bFamilyActivityPicker\b|\bManagedSettingsStore\b',
    'com.apple.developer.usernotifications.critical-alerts': r'\.criticalAlert\b|defaultCritical',
    'com.apple.developer.weatherkit': r'\bWeatherService\b',
    'com.apple.developer.icloud-container-identifiers': r'\bCKContainer\b|NSUbiquitous|NSPersistentCloudKitContainer|cloudKitDatabase|ubiquityIdentityToken',
}


def entitlements_unused(c):
    """§80 — 2.5.1: a sensitive capability with no code that uses it draws review
    questions (and HealthKit/HomeKit/Network Extension require visible functionality).
    Only capabilities with an unambiguous API are checked; extension targets count."""
    src = c['src']
    for p, value in sorted(c['plists'].items(), key=lambda x: str(x[0])):
        if p.suffix != '.entitlements':
            continue
        for key, pattern in sorted(ENTITLEMENT_USE.items()):
            if value.get(key) and not hit_file(src, pattern):
                return outcome(True, 'Entitlement %s is enabled but no code uses its API: remove the capability, or make the feature that needs it visible and explain it in the review notes.' % key, p)
    return outcome(reason='Every checked sensitive entitlement has matching API use (or none are enabled).')


CLAIM = re.compile(r'100%\s*(?:offline|private)|works?\s+(?:fully\s+)?offline|no\s+internet\s+(?:required|needed|connection)|'
                   r'never\s+leaves?\s+your\s+(?:device|phone|iphone)|stays?\s+on\s+your\s+(?:device|phone|iphone)|'
                   r'(?:all|everything)\s+(?:is\s+)?(?:processed\s+)?on[- ]device|no\s+data\s+(?:is\s+)?collected|'
                   r'we\s+(?:do\s+not|don.t|never)\s+collect', re.I)
FLOW = re.compile(r'api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai|openrouter\.ai|'
                  r'\bimport\s+(?:FirebaseAnalytics|Firebase|Mixpanel|Amplitude|Segment|PostHog|AppsFlyerLib|Adjust|FBSDKCoreKit|GoogleMobileAds|Sentry|Bugsnag)\b|'
                  r'Analytics\.logEvent|Mixpanel\.mainInstance|Amplitude\.instance|AppsFlyerLib\.shared|ASIdentifierManager', re.I)


def privacy_claims(c):
    """§81 — 2.3.1 / 5.1.1: an offline, on-device or no-data-collected claim in store
    metadata or UI copy while the code sends data to a cloud AI provider or runs an
    analytics/attribution/crash SDK. The claim may be precise (e.g. processing is local,
    crash reports are not) — a human reads both sides."""
    claim, where = None, None
    try:
        files = metadata_files(c, ['name', 'subtitle', 'description', 'promotional_text', 'keywords'])
    except ValueError:
        files = []
    for p in files:
        m = CLAIM.search(checked_text(p))
        if m:
            claim, where = m.group(0), p
            break
    if not claim:
        for p, text in list(c['resources'].items()) + list(release_source(c).items()):
            for literal in re.findall(r'"([^"\n]{8,300})"', text):
                m = CLAIM.search(literal)
                if m:
                    claim, where = m.group(0), p
                    break
            if claim:
                break
    if not claim:
        return outcome(reason='No offline / on-device / no-data-collected claim found.')
    flow = next(((p, m.group(0)) for p, t in release_source(c).items() for m in [FLOW.search(t)] if m), None)
    if not flow:
        return outcome(reason='Privacy/offline claim ("%s") with no cloud-AI or analytics data flow detected.' % claim)
    return outcome(True, 'Claim "%s" (%s) while %s sends data off the device (%s): make the claim precise or remove the data flow; claims that contradict the app are misleading metadata (2.3.1) and privacy misrepresentation (5.1.1).' % (claim, where.name, flow[0].name, flow[1]), where)


CHECKS = {'release-notes-specificity': release_notes, 'device-restart-instructions': restart,
          'browser-engine': browser, 'intent-handler-parity': intents,
          'call-filter-controls': call_filter, 'face-authentication': face_auth,
          'document-browser-access': documents, 'extension-bundle-parity': extension_parity,
          'matter-extension': matter, 'extension-advertising': extension_ads,
          'ar-integration-depth': ar_depth, 'companion-app-required': companion,
          'game-center-id-sharing': game_ids, 'metadata-emoji': emoji,
          'miniapp-native-bridge': miniapp, 'apple-endorsement-claims': endorsements,
          'review-mode-gate': review_gate,
          'portfolio-similarity': portfolio, 'release-debug-build': release_config,
          'embedded-secret': secrets, 'localization-format-mismatch': localization_format,
          'purpose-string-localization': permission_localization,
          'storekit-transaction-listener': transaction_listener,
          'bonjour-services-missing': bonjour, 'entitlement-unused': entitlements_unused,
          'privacy-claim-contradiction': privacy_claims}


def evaluate(root, metadata, main, excludes, portfolio=()):
    c = context(root, metadata, main, excludes, portfolio)
    result = {}
    independent = {'release-notes-specificity', 'metadata-emoji', 'apple-endorsement-claims',
                   'portfolio-similarity'}
    if c['gaps']:
        result['_input_gaps'] = {'count': len(set(c['gaps'])), 'paths': sorted(set(c['gaps']))[:3]}
    for key, check in CHECKS.items():
        if key not in independent and not c['src']:
            result[key] = outcome(skip=True, reason='Source directory unavailable or no source files were read.')
            continue
        if key in {'intent-handler-parity', 'companion-app-required'} and not c['main']:
            result[key] = outcome(skip=True, reason='Main Info.plist unavailable for manifest comparison.')
            continue
        try:
            result[key] = check(c)
        except (OSError, UnicodeError, ValueError) as exc:
            if getattr(exc, 'sanitized', False):
                detail = str(exc)
            else:
                detail = input_error(getattr(exc, 'filename', None) or 'input', exc, root) + ' (' + type(exc).__name__ + ')'
            result[key] = outcome(skip=True, reason='Input could not be completely read: ' + detail)
    for key, row in result.items():
        if key.startswith('_'):
            continue
        if row['file']:
            try:
                row['file'] = str(pathlib.Path(row['file']).relative_to(root))
            except ValueError:
                row['file'] = pathlib.Path(row['file']).name
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=pathlib.Path, required=True)
    parser.add_argument('--metadata', type=pathlib.Path, required=True)
    parser.add_argument('--plist', type=pathlib.Path, required=True)
    parser.add_argument('--exclude-dir', action='append', default=[])
    parser.add_argument('--portfolio', action='append', default=[], type=pathlib.Path,
                        help='sibling app repo to compare for 4.3(a); repeatable (opt-in §73)')
    args = parser.parse_args()
    print(json.dumps(evaluate(args.root.resolve(), args.metadata.resolve(), args.plist.resolve(), args.exclude_dir,
                              [p.resolve() for p in args.portfolio])))


if __name__ == '__main__':
    main()
