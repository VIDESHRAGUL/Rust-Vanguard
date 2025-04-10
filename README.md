# Rust-Vanguard: Game Security Demonstration Platform

![Rust-Vanguard Logo](/public/images/logo.png)

## Project Overview

Rust-Vanguard is an educational platform that demonstrates game security concepts, including cheats and anti-cheat systems. The project uses Rust for the core security components, with games implemented in JavaScript/TypeScript for the web interface.

## Purpose

This platform is designed to:

1. Demonstrate common game security vulnerabilities
2. Show how cheats exploit these vulnerabilities
3. Illustrate how anti-cheat systems detect and prevent cheating
4. Provide an educational resource for understanding game security

## Project Structure

- **Frontend**: Next.js with React and TypeScript
- **Security Core**: Rust compiled to WebAssembly (Wasm)
- **Games**: Simple implementations of classic games
- **Cheat Systems**: One unique vulnerability exploit per game
- **Anti-Cheat Systems**: Corresponding protection mechanisms

## Games and Vulnerabilities

### 1. Memory Match
- **Vulnerability**: Buffer Overflow
- **Cheat**: Reveals all card positions by overflowing the memory buffer that stores card states
- **Anti-Cheat**: Memory Integrity Verification that validates memory boundaries

### 2. Minesweeper
- **Vulnerability**: Memory Injection
- **Cheat**: Injects code to reveal mine locations
- **Anti-Cheat**: Process Monitoring that detects unauthorized memory modifications

### 3. Number Guessing
- **Vulnerability**: API Manipulation
- **Cheat**: Intercepts API responses to reveal the target number
- **Anti-Cheat**: Request Validation that verifies the integrity of API calls

### 4. Space Shooter
- **Vulnerability**: Time Manipulation
- **Cheat**: Slows down game time to give the player an advantage
- **Anti-Cheat**: Server-side Verification that ensures consistent game timing

### 5. Puzzle Slide
- **Vulnerability**: Code Injection
- **Cheat**: Injects code to show the solution path
- **Anti-Cheat**: Code Integrity Checking that prevents unauthorized code execution

### 6. Tic Tac Toe
- **Vulnerability**: Logic Manipulation
- **Cheat**: Forces the AI to make suboptimal moves
- **Anti-Cheat**: State Validation that ensures game logic follows expected patterns

## How It Works

### Rust Security Core

The security components are written in Rust and compiled to WebAssembly, providing:

1. Memory safety through Rust's ownership model
2. High performance for real-time monitoring
3. Cross-platform compatibility via WebAssembly

```rust
// Example Rust anti-cheat code (simplified)
pub fn verify_memory_integrity(memory_region: &[u8], expected_hash: &str) -> bool {
    let actual_hash = calculate_hash(memory_region);
    actual_hash == expected_hash
}

