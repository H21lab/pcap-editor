import { test, expect } from '@playwright/test';

test.use({ baseURL: 'http://localhost:3000' });

test.describe('Protocol Decode Verification', () => {

  test('SIGTRAN Python Editor Decoding', async ({ page }) => {
    test.setTimeout(120000);
    await page.goto('/');

    // Upload SIGTRAN pcap
    const filePath = 'RegressionTestsInput/sigtran.pcap';
    await page.setInputFiles('#file-input', filePath);

    // Select Packet 3
    await page.waitForSelector('.packet-row', { timeout: 30000 });
    await page.locator('.packet-row').nth(2).click();

    // Wait for Detail View - use exact match for layer name
    await page.waitForSelector('span:text-is("eth")');

    // Switch to Python mode
    await page.getByLabel('Python Editor').click();

    // Wait for Pyodide to initialize (can take 60+ seconds)
    await page.waitForSelector('[role="progressbar"]', { state: 'detached', timeout: 90000 }).catch(() => {});

    // Verify Python editor content
    const editor = page.getByTestId('python-editor-input');
    await editor.waitFor({ timeout: 90000 });

    const editorContent = await editor.inputValue();

    // Verify TCAP layer block is present (critical check)
    expect(editorContent).toContain("# --- Layer: TCAP ---");

    // Verify IMSI bytes are in the script
    expect(editorContent).toContain("11111111111111f1");

    // Verify script has proper structure
    expect(editorContent).toContain("from binascii import unhexlify, hexlify");
    expect(editorContent).toContain("def generate_packet():");
    expect(editorContent).toContain("# --- Layer: Ethernet ---");
  });

  test('Basic Protocol Layer Detection', async ({ page }) => {
    test.setTimeout(60000);
    await page.goto('/');

    // Upload a pcap
    const filePath = 'RegressionTestsInput/sigtran.pcap';
    await page.setInputFiles('#file-input', filePath);

    // Wait for packet list
    await page.waitForSelector('.packet-row', { timeout: 30000 });

    // Select first packet
    await page.locator('.packet-row').first().click();

    // Verify basic layers - use exact match for layer names
    await expect(page.locator('span:text-is("eth")').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('span:text-is("ip")').first()).toBeVisible({ timeout: 10000 });
  });

  test('Script Re-encoding Identity Test', async ({ page }) => {
    test.setTimeout(180000);
    await page.goto('/');

    // Upload SIGTRAN pcap
    const filePath = 'RegressionTestsInput/sigtran.pcap';
    await page.setInputFiles('#file-input', filePath);

    // Select Packet 3
    await page.waitForSelector('.packet-row', { timeout: 30000 });
    await page.locator('.packet-row').nth(2).click();

    // Wait for TCAP layer - use exact match
    await page.waitForSelector('span:text-is("tcap")', { timeout: 30000 });

    // Record original IMSI visible in Detail View
    await expect(page.locator('body')).toContainText('111111111111111');

    // Switch to Python Editor
    await page.getByLabel('Python Editor').click();
    await page.waitForSelector('[role="progressbar"]', { state: 'detached', timeout: 90000 }).catch(() => {});
    const editor = page.getByTestId('python-editor-input');
    await expect(editor).toBeVisible({ timeout: 90000 });

    // Verify original IMSI is in the script
    const script = await editor.inputValue();
    expect(script).toContain('11111111111111f1');

    // Apply script WITHOUT changes (identity test)
    await page.getByRole('button', { name: 'Apply Script' }).click();
    await expect(editor).not.toBeVisible({ timeout: 30000 });

    // Verify IMSI is still present (re-encoding preserves original)
    await expect(page.locator('body')).toContainText('111111111111111', { timeout: 30000 });

    // Verify NO malformed packet errors
    await expect(page.locator('text=Malformed Packet')).toHaveCount(0);
  });

});
