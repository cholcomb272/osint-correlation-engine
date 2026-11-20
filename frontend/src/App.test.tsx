import { render, screen } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import App from './App'

vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
  const url = String(input)
  const body = url.includes('/incidents')
    ? { items: [], total: 0 }
    : { active_incidents: 0, recent_anomalies: 0, correlation_candidates: 0, high_confidence_relationships: 0, generated_at: new Date().toISOString(), disclaimer: 'Evidence, not attribution.' }
  return { ok: true, json: async () => body }
}))

test('renders the public dashboard without a credential control', async () => {
  render(<App />)
  expect(await screen.findByText('Infrastructure intelligence overview')).toBeInTheDocument()
  expect(screen.queryByLabelText(/api token/i)).not.toBeInTheDocument()
  expect(screen.getByRole('navigation', { name: 'Primary navigation' })).toBeInTheDocument()
})
