use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use jieba_rs::Jieba;
use serde::Serialize;

use crate::PageInput;

const PAGE_KEYWORD_LIMIT: usize = 8;
const SITE_KEYWORD_LIMIT: usize = 30;
const MAX_GROUPS: usize = 100;
const MAX_GROUP_PAGES: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct KeywordScore {
    pub term: String,
    pub score: f64,
    pub frequency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentHeading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentPageMetrics {
    pub word_count: usize,
    pub character_count: usize,
    pub language: String,
    pub headings: Vec<ContentHeading>,
    pub keywords: Vec<KeywordScore>,
    pub thin_content: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentPageRef {
    pub url: String,
    pub title: Option<String>,
    pub word_count: usize,
    pub character_count: usize,
    pub inbound_links: usize,
    pub keywords: Vec<KeywordScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentGroup {
    pub pages: Vec<ContentPageRef>,
    pub recommended_page: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentAnalysis {
    pub pages_with_content: usize,
    pub thin_content_pages: usize,
    pub thin_pages: Vec<ContentPageRef>,
    pub thin_pages_truncated: bool,
    pub similar_content_groups: Vec<ContentGroup>,
    pub keyword_overlap_groups: Vec<ContentGroup>,
    pub top_keywords: Vec<KeywordScore>,
    pub groups_truncated: bool,
}

pub fn analyze(
    pages: &[PageInput],
    inbound: &HashMap<String, usize>,
) -> (ContentAnalysis, Vec<ContentPageMetrics>) {
    static JIEBA: OnceLock<Jieba> = OnceLock::new();
    let jieba = JIEBA.get_or_init(Jieba::new);
    let mut documents = Vec::with_capacity(pages.len());
    let mut document_frequency = HashMap::<String, usize>::new();
    let mut pages_with_content = 0usize;
    let mut thin_content_pages = 0usize;

    for page in pages {
        let text = page.content_text.as_deref().unwrap_or_default();
        let tokens = tokenize(&jieba, text);
        let character_count = text.chars().filter(|ch| !ch.is_whitespace()).count();
        let cjk_count = text.chars().filter(|ch| is_cjk(*ch)).count();
        let language = if cjk_count == 0 {
            if tokens.is_empty() {
                "unknown"
            } else {
                "english_or_other"
            }
        } else if cjk_count * 5 >= character_count {
            "chinese"
        } else {
            "mixed"
        };
        let eligible = page.error.is_none()
            && page.status_code.is_none_or(|status| status < 400)
            && (!text.is_empty()
                || page
                    .content_type
                    .as_deref()
                    .is_some_and(|value| value.to_ascii_lowercase().contains("text/html")));
        let thin = eligible
            && if cjk_count * 5 >= character_count && cjk_count > 0 {
                cjk_count < 300
            } else {
                tokens.len() < 100
            };
        if !tokens.is_empty() {
            pages_with_content += 1;
        }
        if thin {
            thin_content_pages += 1;
        }
        let unique = tokens.iter().cloned().collect::<HashSet<_>>();
        for token in unique {
            *document_frequency.entry(token).or_default() += 1;
        }
        documents.push((tokens, character_count, language.to_owned(), thin));
    }

    let doc_count = documents.len().max(1) as f64;
    let mut page_metrics = Vec::with_capacity(pages.len());
    let mut site_scores = HashMap::<String, f64>::new();
    let mut site_frequencies = HashMap::<String, usize>::new();
    let mut page_term_sets = Vec::with_capacity(pages.len());
    let mut page_simhashes = Vec::with_capacity(pages.len());

    for (page, (tokens, character_count, language, thin)) in pages.iter().zip(documents.iter()) {
        let mut frequencies = HashMap::<String, usize>::new();
        for token in tokens {
            *frequencies.entry(token.clone()).or_default() += 1;
        }
        let token_count = tokens.len().max(1) as f64;
        let mut scores = frequencies
            .iter()
            .map(|(term, count)| {
                let df = document_frequency.get(term).copied().unwrap_or(1) as f64;
                let idf = ((doc_count + 1.0) / (df + 1.0)).ln() + 1.0;
                let score = (*count as f64 / token_count) * idf;
                (term.clone(), score)
            })
            .collect::<Vec<_>>();
        scores.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (term, score) in &scores {
            *site_scores.entry(term.clone()).or_default() += score;
        }
        for (term, count) in &frequencies {
            *site_frequencies.entry(term.clone()).or_default() += count;
        }
        page_term_sets.push(
            scores
                .iter()
                .take(PAGE_KEYWORD_LIMIT)
                .map(|(term, _)| term.clone())
                .collect::<HashSet<_>>(),
        );
        page_simhashes.push(simhash(tokens));
        let headings = page
            .headings
            .iter()
            .take(100)
            .map(|heading| ContentHeading {
                level: heading.level,
                text: heading.text.clone(),
            })
            .collect();
        page_metrics.push(ContentPageMetrics {
            word_count: tokens.len(),
            character_count: *character_count,
            language: language.clone(),
            headings,
            keywords: scores
                .into_iter()
                .take(PAGE_KEYWORD_LIMIT)
                .map(|(term, score)| KeywordScore {
                    frequency: frequencies.get(&term).copied().unwrap_or_default(),
                    term,
                    score,
                })
                .collect(),
            thin_content: *thin,
        });
    }

    let mut top_keywords = site_scores
        .into_iter()
        .map(|(term, score)| KeywordScore {
            frequency: site_frequencies.get(&term).copied().unwrap_or_default(),
            term,
            score,
        })
        .collect::<Vec<_>>();
    top_keywords.sort_by(|a, b| {
        b.frequency
            .cmp(&a.frequency)
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.term.cmp(&b.term))
    });
    top_keywords.truncate(SITE_KEYWORD_LIMIT);

    let thin_page_refs = pages
        .iter()
        .zip(&page_metrics)
        .enumerate()
        .filter(|(_, (_, metrics))| metrics.thin_content)
        .map(|(_, (page, metrics))| page_ref(page, metrics, inbound))
        .collect::<Vec<_>>();
    let thin_pages_truncated = thin_page_refs.len() > 200;
    let similar_pairs = similar_pairs(&page_simhashes);
    let similar_groups = groups_from_pairs(
        &similar_pairs,
        pages,
        &page_metrics,
        inbound,
        "Pages share highly similar body text; the suggested canonical page has the strongest internal linking.",
    );
    let overlap_pairs = keyword_overlap_pairs(&page_term_sets);
    let overlap_groups = groups_from_pairs(
        &overlap_pairs,
        pages,
        &page_metrics,
        inbound,
        "Pages target several of the same high-weight terms; review their search intent and focus.",
    );
    let groups_truncated = similar_groups.len() > MAX_GROUPS || overlap_groups.len() > MAX_GROUPS;

    (
        ContentAnalysis {
            pages_with_content,
            thin_content_pages,
            thin_pages: thin_page_refs.into_iter().take(200).collect(),
            thin_pages_truncated,
            similar_content_groups: similar_groups.into_iter().take(MAX_GROUPS).collect(),
            keyword_overlap_groups: overlap_groups.into_iter().take(MAX_GROUPS).collect(),
            top_keywords,
            groups_truncated,
        },
        page_metrics,
    )
}

fn tokenize(jieba: &Jieba, text: &str) -> Vec<String> {
    static STOP_WORDS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let stop_words = STOP_WORDS.get_or_init(stop_words);
    jieba
        .cut(text, false)
        .into_iter()
        .map(|token| token.word.trim().to_lowercase())
        .filter(|token| token.chars().any(char::is_alphanumeric))
        .filter(|token| token.chars().filter(|ch| ch.is_alphanumeric()).count() >= 2)
        .filter(|token| !stop_words.contains(token.as_str()))
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .collect()
}

fn stop_words() -> HashSet<&'static str> {
    [
        "a", "an", "and", "are", "as", "at", "be", "been", "being", "but", "by", "can", "could",
        "did", "do", "does", "for", "from", "had", "has", "have", "he", "her", "here", "hers",
        "him", "his", "how", "i", "if", "in", "into", "is", "it", "its", "may", "me", "more",
        "most", "my", "no", "not", "of", "on", "or", "our", "out", "she", "should", "so", "than",
        "that", "the", "their", "them", "then", "there", "these", "they", "this", "those", "to",
        "too", "up", "us", "was", "we", "were", "what", "when", "where", "which", "who", "will",
        "with", "would", "you", "your", "的", "了", "和", "是", "在", "就", "都", "而", "及", "与",
        "着", "或", "一个", "没有", "我们", "你们", "他们", "以及", "因为", "所以", "如果", "这个",
        "这些", "那个", "那些", "可以", "进行", "通过", "对于", "作为", "被", "从", "到", "中",
        "上", "下", "也", "还", "等", "并", "但", "其", "之", "所", "为", "把", "让", "更", "很",
        "最", "已经", "需要", "使用", "提供", "支持", "网站",
    ]
    .into_iter()
    .collect()
}

fn is_cjk(ch: char) -> bool {
    matches!(ch as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF)
}

fn simhash(tokens: &[String]) -> u64 {
    if tokens.is_empty() {
        return 0;
    }
    let mut weights = [0i32; 64];
    for token in tokens {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::hash::Hash::hash(token, &mut hasher);
        let hash = std::hash::Hasher::finish(&hasher);
        for (bit, weight) in weights.iter_mut().enumerate() {
            *weight += if hash & (1u64 << bit) == 0 { -1 } else { 1 };
        }
    }
    weights
        .iter()
        .enumerate()
        .fold(0u64, |hash, (bit, weight)| {
            if *weight >= 0 {
                hash | (1u64 << bit)
            } else {
                hash
            }
        })
}

fn similar_pairs(hashes: &[u64]) -> Vec<(usize, usize)> {
    let mut bands = HashMap::<(usize, u16), Vec<usize>>::new();
    for (index, hash) in hashes.iter().enumerate() {
        if *hash == 0 {
            continue;
        }
        for band in 0..4 {
            bands
                .entry((band, (hash >> (band * 16)) as u16 & 0xffff))
                .or_default()
                .push(index);
        }
    }
    let mut candidates = HashSet::new();
    for members in bands.values().filter(|members| members.len() <= 500) {
        for i in 0..members.len() {
            for j in i + 1..members.len() {
                let (a, b) = (members[i].min(members[j]), members[i].max(members[j]));
                candidates.insert((a, b));
                if candidates.len() >= 250_000 {
                    break;
                }
            }
            if candidates.len() >= 250_000 {
                break;
            }
        }
        if candidates.len() >= 250_000 {
            break;
        }
    }
    candidates
        .into_iter()
        .filter(|(a, b)| (hashes[*a] ^ hashes[*b]).count_ones() <= 3)
        .collect()
}

fn keyword_overlap_pairs(terms: &[HashSet<String>]) -> Vec<(usize, usize)> {
    let mut inverted = HashMap::<&str, Vec<usize>>::new();
    for (index, page_terms) in terms.iter().enumerate() {
        for term in page_terms {
            inverted.entry(term).or_default().push(index);
        }
    }
    let mut overlaps = HashMap::<(usize, usize), u8>::new();
    for members in inverted.values().filter(|members| members.len() <= 500) {
        for i in 0..members.len() {
            for j in i + 1..members.len() {
                let key = (members[i].min(members[j]), members[i].max(members[j]));
                *overlaps.entry(key).or_default() += 1;
            }
        }
    }
    overlaps
        .into_iter()
        .filter_map(|(pair, count)| (count >= 3).then_some(pair))
        .collect()
}

fn groups_from_pairs(
    pairs: &[(usize, usize)],
    pages: &[PageInput],
    metrics: &[ContentPageMetrics],
    inbound: &HashMap<String, usize>,
    reason: &str,
) -> Vec<ContentGroup> {
    let mut parent = (0..pages.len()).collect::<Vec<_>>();
    for (a, b) in pairs {
        let root_a = find_root(&mut parent, *a);
        let root_b = find_root(&mut parent, *b);
        if root_a != root_b {
            parent[root_b] = root_a;
        }
    }
    let mut grouped = HashMap::<usize, Vec<usize>>::new();
    for index in 0..pages.len() {
        let root = find_root(&mut parent, index);
        grouped.entry(root).or_default().push(index);
    }
    let mut groups = grouped
        .into_values()
        .filter(|members| members.len() > 1)
        .map(|members| {
            let recommended = *members
                .iter()
                .max_by_key(|index| {
                    let url = normalize(&pages[**index].url);
                    inbound.get(&url).copied().unwrap_or_default()
                })
                .unwrap();
            let recommended_url = normalize(&pages[recommended].url);
            let mut page_refs = members
                .into_iter()
                .map(|index| page_ref(&pages[index], &metrics[index], inbound))
                .collect::<Vec<_>>();
            page_refs.sort_by(|a, b| {
                b.inbound_links
                    .cmp(&a.inbound_links)
                    .then_with(|| a.url.cmp(&b.url))
            });
            ContentGroup {
                pages: page_refs.into_iter().take(MAX_GROUP_PAGES).collect(),
                recommended_page: recommended_url,
                reason: reason.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        b.pages
            .len()
            .cmp(&a.pages.len())
            .then_with(|| a.recommended_page.cmp(&b.recommended_page))
    });
    groups
}

fn page_ref(
    page: &PageInput,
    metrics: &ContentPageMetrics,
    inbound: &HashMap<String, usize>,
) -> ContentPageRef {
    let url = normalize(&page.url);
    ContentPageRef {
        inbound_links: inbound.get(&url).copied().unwrap_or_default(),
        url,
        title: page.title.clone(),
        word_count: metrics.word_count,
        character_count: metrics.character_count,
        keywords: metrics.keywords.clone(),
    }
}

fn find_root(parent: &mut [usize], index: usize) -> usize {
    if parent[index] != index {
        parent[index] = find_root(parent, parent[index]);
    }
    parent[index]
}

fn normalize(value: &str) -> String {
    crate::normalize_url(value).unwrap_or_else(|| value.to_owned())
}
