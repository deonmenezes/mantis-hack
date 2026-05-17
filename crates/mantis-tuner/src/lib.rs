//! Evolutionary tuner (Phase 3 M3.5).
//!
//! Multi-objective NSGA-II selection over Mantis configuration
//! genomes. Each genome describes a configuration vector
//! (synthesizer prompt templates, primitive parameter defaults,
//! oracle thresholds, fuzzer seed selections). Each evaluation
//! produces a fitness vector (claim verification rate, latency,
//! request budget per verified claim). The tuner returns the
//! Pareto-front retention set after each generation (PRD §10.6).
//!
//! Phase 3 M3.5 ships the NSGA-II fast non-dominated sort + crowding
//! distance pieces. The evaluator-feedback loop is wired up in
//! M3.5b once a real engagement corpus exists to evaluate against.

use serde::{Deserialize, Serialize};

/// A single fitness vector. Higher values = better on every axis
/// (the tuner inverts cost-style metrics before calling).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fitness {
    pub values: Vec<f64>,
}

impl Fitness {
    pub fn new(values: Vec<f64>) -> Self {
        Self { values }
    }

    /// Pareto dominance: `self` dominates `other` iff
    /// `self ≥ other` on every axis and `self > other` on at least
    /// one axis.
    pub fn dominates(&self, other: &Fitness) -> bool {
        if self.values.len() != other.values.len() {
            return false;
        }
        let mut at_least_one_better = false;
        for (a, b) in self.values.iter().zip(&other.values) {
            if a < b {
                return false;
            }
            if a > b {
                at_least_one_better = true;
            }
        }
        at_least_one_better
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Individual<G> {
    pub genome: G,
    pub fitness: Fitness,
}

/// Fast non-dominated sort. Returns the population split into
/// Pareto fronts, lowest-rank-first.
pub fn fast_nondominated_sort<G: Clone>(population: Vec<Individual<G>>) -> Vec<Vec<Individual<G>>> {
    let n = population.len();
    if n == 0 {
        return vec![];
    }
    let mut dominated: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut domination_count: Vec<usize> = vec![0; n];
    let mut fronts: Vec<Vec<usize>> = vec![Vec::new()];

    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            if population[i].fitness.dominates(&population[j].fitness) {
                dominated[i].push(j);
            } else if population[j].fitness.dominates(&population[i].fitness) {
                domination_count[i] += 1;
            }
        }
        if domination_count[i] == 0 {
            fronts[0].push(i);
        }
    }

    let mut current = 0;
    while !fronts[current].is_empty() {
        let mut next_front: Vec<usize> = Vec::new();
        for &i in &fronts[current] {
            for &j in &dominated[i] {
                domination_count[j] -= 1;
                if domination_count[j] == 0 {
                    next_front.push(j);
                }
            }
        }
        if next_front.is_empty() {
            break;
        }
        fronts.push(next_front);
        current += 1;
    }

    fronts
        .into_iter()
        .map(|front| {
            front
                .into_iter()
                .map(|i| population[i].clone())
                .collect::<Vec<_>>()
        })
        .filter(|front| !front.is_empty())
        .collect()
}

/// Crowding distance per individual within a front. Returns
/// distances in the same order as `front`.
pub fn crowding_distance<G>(front: &[Individual<G>]) -> Vec<f64> {
    let n = front.len();
    if n == 0 {
        return vec![];
    }
    if n <= 2 {
        return vec![f64::INFINITY; n];
    }
    let m = front[0].fitness.values.len();
    let mut distances = vec![0.0; n];

    for objective in 0..m {
        // Indices into `front`, sorted ascending by this objective.
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by(|&a, &b| {
            front[a].fitness.values[objective]
                .partial_cmp(&front[b].fitness.values[objective])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        distances[order[0]] = f64::INFINITY;
        distances[order[n - 1]] = f64::INFINITY;
        let min_val = front[order[0]].fitness.values[objective];
        let max_val = front[order[n - 1]].fitness.values[objective];
        let range = max_val - min_val;
        if range <= 0.0 {
            continue;
        }
        for k in 1..n - 1 {
            let next = front[order[k + 1]].fitness.values[objective];
            let prev = front[order[k - 1]].fitness.values[objective];
            distances[order[k]] += (next - prev) / range;
        }
    }
    distances
}

/// NSGA-II environmental selection: take the best `keep` individuals
/// across the sorted fronts, breaking ties within the last partial
/// front by crowding distance (descending).
pub fn select_next_generation<G: Clone>(
    population: Vec<Individual<G>>,
    keep: usize,
) -> Vec<Individual<G>> {
    if population.is_empty() || keep == 0 {
        return vec![];
    }
    let fronts = fast_nondominated_sort(population);
    let mut selected: Vec<Individual<G>> = Vec::with_capacity(keep);
    for front in fronts {
        if selected.len() + front.len() <= keep {
            selected.extend(front);
        } else {
            let remaining = keep - selected.len();
            let mut indexed: Vec<(usize, f64)> =
                crowding_distance(&front).into_iter().enumerate().collect();
            indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            for (idx, _) in indexed.into_iter().take(remaining) {
                selected.push(front[idx].clone());
            }
            break;
        }
        if selected.len() >= keep {
            break;
        }
    }
    selected.truncate(keep);
    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ind(values: Vec<f64>) -> Individual<&'static str> {
        Individual {
            genome: "g",
            fitness: Fitness::new(values),
        }
    }

    #[test]
    fn dominance_basic() {
        let a = Fitness::new(vec![1.0, 1.0]);
        let b = Fitness::new(vec![0.5, 0.5]);
        let c = Fitness::new(vec![1.0, 0.5]); // ties with a on one axis
        assert!(a.dominates(&b));
        assert!(!b.dominates(&a));
        assert!(a.dominates(&c));
        assert!(!c.dominates(&a));
    }

    #[test]
    fn dominance_requires_at_least_one_strictly_better() {
        let a = Fitness::new(vec![1.0, 1.0]);
        let b = Fitness::new(vec![1.0, 1.0]);
        assert!(!a.dominates(&b));
        assert!(!b.dominates(&a));
    }

    #[test]
    fn dominance_handles_mismatched_dimensions() {
        let a = Fitness::new(vec![1.0, 1.0]);
        let b = Fitness::new(vec![1.0]);
        assert!(!a.dominates(&b));
    }

    #[test]
    fn fast_sort_with_two_fronts() {
        let population = vec![
            ind(vec![1.0, 1.0]), // dominates everyone below
            ind(vec![0.5, 0.5]),
            ind(vec![0.4, 0.4]),
        ];
        let fronts = fast_nondominated_sort(population);
        assert!(fronts.len() >= 2);
        assert_eq!(fronts[0].len(), 1);
        assert_eq!(fronts[0][0].fitness.values, vec![1.0, 1.0]);
    }

    #[test]
    fn fast_sort_pareto_front_is_first() {
        // (1, 0), (0, 1) and (0.6, 0.6) are mutually non-dominated
        // (each beats the others on at least one axis), so they all
        // share the first front. (0.3, 0.3) is dominated by (0.6,
        // 0.6) and lands in front 2.
        let population = vec![
            ind(vec![1.0, 0.0]),
            ind(vec![0.0, 1.0]),
            ind(vec![0.6, 0.6]),
            ind(vec![0.3, 0.3]),
        ];
        let fronts = fast_nondominated_sort(population);
        assert_eq!(fronts.len(), 2);
        assert_eq!(fronts[0].len(), 3);
        assert_eq!(fronts[1].len(), 1);
    }

    #[test]
    fn crowding_distance_extremes_are_infinite() {
        let front = vec![
            ind(vec![0.0, 1.0]),
            ind(vec![0.5, 0.5]),
            ind(vec![1.0, 0.0]),
        ];
        let d = crowding_distance(&front);
        let inf_count = d.iter().filter(|x| x.is_infinite()).count();
        assert_eq!(inf_count, 2);
        // The middle individual has a finite, positive distance.
        let middle = d.iter().find(|x| x.is_finite()).copied().unwrap();
        assert!(middle > 0.0);
    }

    #[test]
    fn select_returns_pareto_front_when_keep_matches_front_size() {
        let population = vec![
            ind(vec![1.0, 0.0]),
            ind(vec![0.0, 1.0]),
            ind(vec![0.4, 0.4]),
        ];
        let kept = select_next_generation(population, 2);
        assert_eq!(kept.len(), 2);
        // Both individuals should be on the Pareto front.
        for k in &kept {
            assert!(k.fitness.values == vec![1.0, 0.0] || k.fitness.values == vec![0.0, 1.0]);
        }
    }

    #[test]
    fn select_empty_population_returns_empty() {
        let kept = select_next_generation::<&'static str>(vec![], 5);
        assert!(kept.is_empty());
    }
}
