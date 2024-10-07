use eframe::egui;
use rand::Rng;

const SIGNATURE: [u8; 10] = *b"TARGET_NUM"; // Define the signature

#[repr(C)] // Ensure proper layout
struct SecretNumberHolder {
    signature: [u8; 10],
    secret_number: u32,
}

struct GuessingGame {
    secret_holder: SecretNumberHolder,
    guess: String,
    message: String,
}

impl Default for GuessingGame {
    fn default() -> Self {
        let mut game = Self {
            secret_holder: SecretNumberHolder {
                signature: SIGNATURE,
                secret_number: rand::thread_rng().gen_range(1..=100),
            },
            guess: String::new(),
            message: "Guess the number between 1 and 100!".to_owned(),
        };
        game.set_secret_number(game.secret_holder.secret_number); // Set the secret number
        game
    }
}

impl eframe::App for GuessingGame {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Number Guessing Game");

            // Display the current message (instructions or result)
            ui.label(&self.message);

            // Input field for the player's guess
            ui.text_edit_singleline(&mut self.guess);

            // Button to submit the guess
            if ui.button("Submit Guess").clicked() {
                // Parse the guess from the user input
                match self.guess.trim().parse::<u32>() {
                    Ok(guess) => {
                        if guess < self.secret_holder.secret_number {
                            self.message = "Too small!".to_owned();
                        } else if guess > self.secret_holder.secret_number {
                            self.message = "Too big!".to_owned();
                        } else {
                            self.message = "You guessed it!".to_owned();
                        }
                    }
                    Err(_) => {
                        self.message = "Please enter a valid number.".to_owned();
                    }
                }
            }

            // Button to restart the game
            if ui.button("Restart").clicked() {
                self.set_secret_number(rand::thread_rng().gen_range(1..=100)); // Use the method here
                self.guess.clear();
                self.message = "Guess the number between 1 and 100!".to_owned();
            }
        });
    }
}

impl GuessingGame {
    // Set the secret number
    fn set_secret_number(&mut self, number: u32) {
        self.secret_holder.secret_number = number; // Set the secret number
        
        // Log the address and the secret number
        let address = &self.secret_holder as *const _ as usize; // Get the address of secret_holder
        println!("Generated secret number: {} at address: 0x{:X}", number, address);
    }

    // Function to get the secret number for the anti-cheat
    #[no_mangle]
    pub extern "C" fn get_secret_number() -> u32 {
        unsafe { SECRET_NUMBER.secret_number } // Directly return the secret number from the struct
    }
}

// Create a static instance of SecretNumberHolder
static mut SECRET_NUMBER: SecretNumberHolder = SecretNumberHolder {
    signature: SIGNATURE,
    secret_number: 0,
};

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Number Guessing Game",
        options,
        Box::new(|_cc| Ok(Box::new(GuessingGame::default()))),
    )
}
