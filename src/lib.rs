pub mod rules;

use regex::Regex;

pub struct Rule {
    pub id: String,
    pub regex: Regex,
    pub entropy: Option<f64>,
}

pub struct Redactor {
    rules: Vec<Rule>,
    placeholder: String,
}

pub struct Outcome {
    pub text: String,
    pub counts: Vec<(String, usize)>,
}

impl Outcome {
    pub fn total(&self) -> usize {
        self.counts.iter().map(|(_, c)| c).sum()
    }
}

pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut entropy = 0.0_f64;
    for &count in freq.iter() {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_same_char() {
        let e = shannon_entropy("AAAA");
        assert!(e < 0.1);
    }

    #[test]
    fn entropy_high() {
        let e = shannon_entropy("sk-proj-abc123ABC/+def456DEF=");
        assert!(e > 4.0);
    }
}
