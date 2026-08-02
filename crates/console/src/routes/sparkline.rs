pub(crate) fn render(values: &[i64], width: u32, height: u32, color: &str) -> String {
    if values.is_empty() {
        return String::new();
    }
    let max = values.iter().copied().max().unwrap_or(1).max(1) as f64;
    let step = width as f64 / (values.len().max(2) - 1) as f64;
    let points: String = values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = i as f64 * step;
            let y = height as f64 - (v as f64 / max * (height as f64 - 2.0)) - 1.0;
            format!("{:.1},{:.1}", x, y)
        })
        .collect::<Vec<_>>()
        .join(" ");

    format!(
        "<svg viewBox=\"0 0 {width} {height}\" style=\"width:100%;height:{height}px;display:block\">\
         <polyline points=\"{points}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.5\" stroke-linejoin=\"round\"/>\
         </svg>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_valid_svg() {
        let svg = render(&[0, 5, 3, 8, 2], 120, 30, "#d99a3d");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("polyline"));
        assert!(svg.contains("#d99a3d"));
    }

    #[test]
    fn render_all_zeros_produces_flat_line() {
        let svg = render(&[0, 0, 0, 0], 120, 30, "#d99a3d");
        assert!(svg.contains("polyline"));
    }

    #[test]
    fn render_single_value() {
        let svg = render(&[5], 120, 30, "#d99a3d");
        assert!(svg.contains("polyline"));
    }

    #[test]
    fn render_empty_returns_empty() {
        assert_eq!(render(&[], 120, 30, "#d99a3d"), "");
    }
}
