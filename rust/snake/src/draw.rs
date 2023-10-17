use piston_window::types::Color;
use piston_window::{rectangle, Context, G2d};

const BLOCK_SIZE: f64 = 25.0;

pub fn to_coord(game_coord: f32) -> f64 {
    (game_coord as f64) * BLOCK_SIZE
}

pub fn to_coord_u32(game_coord: u32) -> u32 {
    game_coord * (BLOCK_SIZE as u32)
}

pub fn draw_block(color: Color, x: i32, y: i32, con: &Context, g: &mut G2d) {
    let gui_x = to_coord(x as f32);
    let gui_y = to_coord(y as f32);
    rectangle(
        color,
        [gui_x, gui_y, BLOCK_SIZE, BLOCK_SIZE],
        con.transform,
        g,
    );
}

pub fn draw_rectangle(
    color: Color,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    con: &Context,
    g: &mut G2d,
) {
    let x = to_coord(x as f32);
    let y = to_coord(y as f32);
    rectangle(
        color,
        [
            x,
            y,
            BLOCK_SIZE * (width as f64),
            BLOCK_SIZE * (height as f64),
        ],
        con.transform,
        g,
    );
}
