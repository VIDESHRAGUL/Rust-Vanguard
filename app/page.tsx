"use client"

import { useEffect, useState } from "react"
import LoginPage from "@/components/login-page"
import Dashboard from "@/components/dashboard"

export default function Home() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [lastActivity, setLastActivity] = useState<number | null>(null)
  const [mounted, setMounted] = useState(false)

  // Handle client-side mounting
  useEffect(() => {
    setMounted(true)
    setLastActivity(Date.now())
  }, [])

  // Check for inactivity
  useEffect(() => {
    if (!mounted || !lastActivity) return

    const checkInactivity = () => {
      const now = Date.now()
      const inactiveTime = now - lastActivity

      // Logout after 30 minutes of inactivity (1800000 ms)
      if (isLoggedIn && inactiveTime > 1800000) {
        setIsLoggedIn(false)
        alert("You have been logged out due to inactivity.")
      }
    }

    const interval = setInterval(checkInactivity, 60000) // Check every minute

    // Reset activity timer on user interaction
    const resetTimer = () => setLastActivity(Date.now())
    window.addEventListener("mousemove", resetTimer)
    window.addEventListener("keypress", resetTimer)
    window.addEventListener("click", resetTimer)

    return () => {
      clearInterval(interval)
      window.removeEventListener("mousemove", resetTimer)
      window.removeEventListener("keypress", resetTimer)
      window.removeEventListener("click", resetTimer)
    }
  }, [isLoggedIn, lastActivity, mounted])

  const handleLogin = (username: string, password: string) => {
    if (username === "frey" && password === "frey") {
      setIsLoggedIn(true)
      setLastActivity(Date.now())
    } else {
      alert("Invalid credentials. Please try again.")
    }
  }

  const handleLogout = () => {
    setIsLoggedIn(false)
  }

  // Don't render until client-side hydration is complete
  if (!mounted) {
    return null
  }

  return (
    <main className="min-h-screen">
      {isLoggedIn ? <Dashboard onLogout={handleLogout} /> : <LoginPage onLogin={handleLogin} />}
    </main>
  )
}

