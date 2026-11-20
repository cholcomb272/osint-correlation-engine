import { expect, test } from '@playwright/test'

test('public dashboard loads without credential entry', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Correlation Engine', { exact: true })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Infrastructure intelligence overview' })).toBeVisible()
  await expect(page.getByLabel(/api token/i)).toHaveCount(0)
  await page.getByRole('button', { name: 'Infrastructure Topology' }).click()
  await expect(page.getByRole('heading', { name: 'Infrastructure topology' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Evidence strength' })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Telemetry visibility, not incident proof' })).toBeVisible()
  await expect(page.getByLabel(/show inferred candidates/i)).not.toBeChecked()
  await expect(page.getByLabel(/show investigator hypotheses/i)).not.toBeChecked()
  await expect(page.getByLabel('Layout')).toHaveValue('investigation')
  await expect(page.getByText('Candidate — not causal')).toBeVisible()
})
