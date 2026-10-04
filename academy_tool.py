"""
Minimal structural toolkit for academy.html.

The generator that originally produced this file is gone, so academy.html is now
the source. Editing it by hand is safe for prose, but anything structural --
deleting a lesson, reordering, renaming -- has to keep four things in step:
the lesson id, the data-title, the "Lesson N of M" counter, and the lesson list
printed on the syllabus page. This module does that, and validate() checks it.

Usage
-----
    python academy_tool.py                 # counts + structural check

    import academy_tool as A
    s = A.load()                           # academy.html
    A.lessons(s, 's11')                    # [(id, title, offset), ...]
    s = A.delete_lesson(s, 's1-3')         # removes it and renumbers the section
    assert not A.validate(s)               # ids, titles, counters, quiz answers
    A.save(s)

Prose edits need none of this -- edit academy.html directly, then run
validate() before deploying. Deploy = commit academy.html; Railway rebuilds.
"""
import re, sys

LESSON_RE = r'<div class="lesson" id="(?P<id>s\d+-\d+)" data-title="(?P<title>[^"]*)">'

def load(path='academy.html'):
    return open(path, encoding='utf-8').read()

def save(s, path='academy.html'):
    open(path, 'w', encoding='utf-8').write(s)

def _section_span(s, sid):
    a = s.find('<section class="sec" id="%s"' % sid)
    assert a >= 0, 'no section ' + sid
    b = s.find('</section>', a)
    return a, b

def lessons(s, sid):
    a, b = _section_span(s, sid)
    return [(m.group('id'), m.group('title'), a + m.start())
            for m in re.finditer(LESSON_RE, s[a:b])]

def lesson_span(s, lid):
    """Start and end offsets of one <div class="lesson"> block, by nesting depth."""
    a = s.find('<div class="lesson" id="%s"' % lid)
    assert a >= 0, 'no lesson ' + lid
    depth, i = 0, a
    for m in re.finditer(r'<div\b|</div>', s[a:]):
        i = a + m.start()
        depth += 1 if m.group(0) != '</div>' else -1
        if depth == 0:
            return a, i + len('</div>')
    raise AssertionError('unbalanced divs in ' + lid)

def delete_lesson(s, lid):
    """Remove a lesson and renumber its section: ids, titles, counters, syllabus list."""
    sid = lid.split('-')[0]
    before = [t for _, t, _ in lessons(s, sid)]
    doomed = [t for i, t, _ in lessons(s, sid) if i == lid][0]

    a, b = lesson_span(s, lid)
    s = s[:a] + s[b:]

    # renumber the survivors, high to low so ids never collide mid-flight
    rest = lessons(s, sid)
    n = len(rest)
    num = sid[1:]
    for new_i, (old_id, old_title, _) in reversed(list(enumerate(rest, start=1))):
        body = re.sub(r'^\d+\.\d+\s+', '', old_title)
        new_id = '%s-%d' % (sid, new_i)
        new_title = '%s.%d %s' % (num, new_i, body)
        ca, cb = lesson_span(s, old_id)
        blk = s[ca:cb]
        blk = blk.replace('id="%s" data-title="%s"' % (old_id, old_title),
                          'id="%s" data-title="%s"' % (new_id, new_title), 1)
        blk = re.sub(r'<span class="eyebrow">Lesson \d+ of \d+</span>',
                     '<span class="eyebrow">Lesson %d of %d</span>' % (new_i, n), blk, count=1)
        blk = blk.replace('<h3>%s</h3>' % old_title, '<h3>%s</h3>' % new_title, 1)
        s = s[:ca] + blk + s[cb:]

    # the syllabus "Lessons" line for this module
    chip = '<span class="ls">%s</span>' % re.sub(r'^\d+\.\d+\s+', '', doomed)
    for pat in (' <span class="sep">·</span> ' + chip, chip + ' <span class="sep">·</span> ', chip):
        if pat in s:
            s = s.replace(pat, '', 1)
            break
    return s

def validate(s):
    """Structural invariants. Returns a list of problems; empty means clean."""
    bad = []
    for m in re.finditer(r'<section class="sec" id="(s\d+)"', s):
        sid = m.group(1)
        ls = lessons(s, sid)
        n = len(ls)
        num = sid[1:]
        # Phases 14 and 15 carry no module number, so their lessons are titled
        # in words rather than "N.M ...". Skip the numbering rule for those.
        numbered = all(re.match(r'\d+\.\d+ ', t) for _, t, _ in ls) if ls else False
        for i, (lid, title, off) in enumerate(ls, start=1):
            if lid != '%s-%d' % (sid, i):
                bad.append('%s: lesson %d has id %s' % (sid, i, lid))
            if numbered and not title.startswith('%s.%d ' % (num, i)):
                bad.append('%s: lesson %d titled %r' % (sid, i, title))
            a, b = lesson_span(s, lid)
            c = re.search(r'Lesson (\d+) of (\d+)', s[a:b])
            if c and (int(c.group(1)) != i or int(c.group(2)) != n):
                bad.append('%s/%s: counter says %s of %s, expected %d of %d'
                           % (sid, lid, c.group(1), c.group(2), i, n))
    # every quiz question has exactly one correct answer
    for qz in re.findall(r'<div class="qz"(.*?)<div class="res">', s, re.S):
        qid = re.search(r'data-quiz="([^"]+)"', qz)
        for q in re.findall(r'<div class="q">(.*?)<div class="why">', qz, re.S):
            if len(re.findall(r'data-c', q)) != 1:
                bad.append('quiz %s: a question has != 1 correct answer'
                           % (qid.group(1) if qid else '?'))
    return bad

if __name__ == '__main__':
    s = load()
    print('sections:', len(re.findall(r'<section class="sec" id="s\d+"', s)))
    print('lessons :', len(re.findall(LESSON_RE, s)))
    probs = validate(s)
    print('problems:', len(probs))
    for p in probs[:20]:
        print('  -', p)
