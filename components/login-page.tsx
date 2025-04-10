"use client"

import type React from "react"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Shield, ShieldAlert, Gamepad2 } from "lucide-react"

interface LoginPageProps {
  onLogin: (username: string, password: string) => void
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onLogin(username, password)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-gray-900 to-gray-800">
      <div className="absolute inset-0 bg-[url('/placeholder.svg?height=1080&width=1920')] bg-cover bg-center opacity-10"></div>
      <div className="relative z-10 w-full max-w-md px-4">
        <div className="flex justify-center mb-8">
          <div className="flex items-center gap-2">
            <Shield className="h-10 w-10 text-green-500" />
            <h1 className="text-3xl font-bold text-white">Rust-Vanguard</h1>
          </div>
        </div>

        <Card className="border-gray-700 bg-gray-800/90 backdrop-blur-sm">
          <CardHeader className="space-y-1">
            <CardTitle className="text-2xl text-white flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-green-500" />
              <span>Security Login</span>
            </CardTitle>
            <CardDescription className="text-gray-400">
              Enter your credentials to access the game security platform
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-gray-300">
                  Username
                </Label>
                <Input
                  id="username"
                  placeholder="Enter your username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-500"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password" className="text-gray-300">
                  Password
                </Label>
                <Input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-500"
                  required
                />
              </div>
            </form>
          </CardContent>
          <CardFooter>
            <Button onClick={handleSubmit} className="w-full bg-green-600 hover:bg-green-700 text-white">
              Login to Platform
            </Button>
          </CardFooter>
        </Card>

        <div className="mt-6 text-center text-gray-500 text-sm">
          <p>Demo credentials: username: frey | password: frey</p>
          <p className="mt-2 flex items-center justify-center gap-1">
            <Gamepad2 className="h-4 w-4" /> Game Security Demonstration Platform
          </p>
        </div>
      </div>
    </div>
  )
}

