//! Unit tests for the pure window-placement math in `clipboard_listener.rs`.
use super::*;

// A 1920x1040 work area (1080p minus a 40px taskbar) and a 530x500 window.
const WORK: (i32, i32, i32, i32) = (0, 0, 1920, 1040);
const SIZE: (i32, i32) = (530, 500);

#[test]
fn opens_with_top_left_corner_at_the_pointer() {
    assert_eq!(compute_position(WORK, (400, 300), SIZE, true), (400, 300));
}

#[test]
fn flips_above_the_pointer_when_there_is_no_room_below() {
    // 900 + 500 > 1040 -> placed so its bottom edge sits at the pointer.
    assert_eq!(compute_position(WORK, (400, 900), SIZE, true), (400, 400));
}

#[test]
fn shifts_left_when_it_would_overflow_the_right_edge() {
    assert_eq!(compute_position(WORK, (1800, 300), SIZE, true), (1920 - 530, 300));
}

#[test]
fn stays_inside_the_area_when_the_pointer_is_in_a_corner() {
    assert_eq!(compute_position(WORK, (1919, 1039), SIZE, true), (1920 - 530, 1039 - 500));
    assert_eq!(compute_position(WORK, (0, 0), SIZE, true), (0, 0));
}

#[test]
fn respects_a_work_area_that_does_not_start_at_the_origin() {
    // Second monitor placed to the right of and above the primary one.
    let work = (1920, -200, 3840, 840);
    assert_eq!(compute_position(work, (2000, 100), SIZE, true), (2000, 100));
    // Pointer near its bottom edge: flips above, still inside this monitor.
    assert_eq!(compute_position(work, (2000, 800), SIZE, true), (2000, 300));
    // Left of the monitor can't be crossed even if the pointer is at the very edge.
    assert_eq!(compute_position(work, (1920, 100), SIZE, true).0, 1920);
}

#[test]
fn flipped_window_never_goes_above_the_top_of_the_area() {
    // Tiny area: neither below nor above fits, so the top edge wins.
    let work = (0, 0, 1000, 400);
    assert_eq!(compute_position(work, (100, 350), SIZE, true), (100, 0));
}

#[test]
fn centered_mode_ignores_the_pointer_and_uses_the_real_window_size() {
    let centered = compute_position(WORK, (5, 5), SIZE, false);
    assert_eq!(centered, ((1920 - 530) / 2, (1040 - 500) / 2));
    // A different size must be centered with *its* dimensions (the old code hardcoded 360x380).
    assert_eq!(compute_position(WORK, (5, 5), (360, 380), false), ((1920 - 360) / 2, (1040 - 380) / 2));
}

#[test]
fn window_larger_than_the_area_is_pinned_to_the_top_left() {
    let work = (0, 0, 300, 300);
    assert_eq!(compute_position(work, (100, 100), SIZE, true), (0, 0));
    assert_eq!(compute_position(work, (100, 100), SIZE, false), (0, 0));
}
