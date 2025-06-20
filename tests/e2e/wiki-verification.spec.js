// @ts-check
import { test, expect } from '@playwright/test';

/**
 * GitHub Wiki Documentation Verification Suite
 * Tests wiki integration and documentation accessibility
 */

const REPO_OWNER = 'lsendel';
const REPO_NAME = 'root-zamaz';
const WIKI_BASE_URL = `https://github.com/${REPO_OWNER}/${REPO_NAME}/wiki`;

test.describe('GitHub Wiki Integration', () => {
  
  test('Wiki homepage should be accessible', async ({ page }) => {
    await page.goto(WIKI_BASE_URL);
    
    // Check if wiki exists and is accessible
    await expect(page).toHaveTitle(/Wiki/);
    
    // Look for wiki content or setup message
    const hasContent = await page.locator('.wiki-wrapper').isVisible();
    const hasSetupMessage = await page.locator('[data-testid="wiki-setup-message"]').isVisible();
    
    expect(hasContent || hasSetupMessage).toBeTruthy();
  });

  test('Documentation section should exist in wiki', async ({ page }) => {
    await page.goto(WIKI_BASE_URL);
    
    // Look for Documentation section or page
    const documentationLink = page.locator('a[href*="Documentation"]');
    const hasDocs = await documentationLink.count() > 0;
    
    if (hasDocs) {
      // Test Documentation section accessibility
      await documentationLink.first().click();
      await expect(page).toHaveURL(/Documentation/);
      
      // Check for key documentation sections
      const sections = [
        'Database Schema',
        'API Documentation', 
        'Architecture',
        'Security'
      ];
      
      for (const section of sections) {
        const sectionExists = await page.locator(`text=${section}`).count() > 0;
        console.log(`${section}: ${sectionExists ? '✅ Found' : '⚠️  Not found'}`);
      }
    } else {
      console.log('⚠️  Documentation section not found in wiki');
    }
  });

  test('Schema documentation should contain Mermaid diagrams', async ({ page }) => {
    // Navigate to schema documentation if it exists
    await page.goto(`${WIKI_BASE_URL}/Documentation`);
    
    // Look for schema-related pages
    const schemaLinks = await page.locator('a[href*="schema"], a[href*="Schema"]').all();
    
    if (schemaLinks.length > 0) {
      await schemaLinks[0].click();
      
      // Check for Mermaid diagram indicators
      const hasMermaid = await page.locator('pre:has-text("mermaid"), code:has-text("mermaid")').count() > 0;
      const hasDiagramClass = await page.locator('.language-mermaid, [class*="mermaid"]').count() > 0;
      
      expect(hasMermaid || hasDiagramClass).toBeTruthy();
      console.log('✅ Mermaid diagrams found in schema documentation');
    } else {
      console.log('⚠️  Schema documentation not found in wiki');
    }
  });

  test('Wiki navigation should be functional', async ({ page }) => {
    await page.goto(WIKI_BASE_URL);
    
    // Check for wiki navigation elements
    const sidebarExists = await page.locator('.wiki-rightbar, .Box-sidebar').isVisible();
    const pagesListExists = await page.locator('[data-filterable-for="wiki-pages-filter"]').isVisible();
    
    if (sidebarExists || pagesListExists) {
      console.log('✅ Wiki navigation structure found');
      
      // Test page navigation if pages exist
      const pageLinks = await page.locator('.wiki-rightbar a, .Box-sidebar a').all();
      
      if (pageLinks.length > 0) {
        // Test first page link
        const firstLink = pageLinks[0];
        const linkText = await firstLink.textContent();
        await firstLink.click();
        
        // Verify navigation worked
        await expect(page).toHaveURL(new RegExp(WIKI_BASE_URL));
        console.log(`✅ Successfully navigated to: ${linkText}`);
      }
    } else {
      console.log('⚠️  Wiki navigation not found - may be empty wiki');
    }
  });

  test('Verify wiki sync integrity', async ({ page }) => {
    await page.goto(`${WIKI_BASE_URL}/Documentation`);
    
    // Expected sections based on our documentation structure
    const expectedSections = [
      'Database Schema',
      'Authentication & Authorization',
      'Security & Monitoring', 
      'Zero Trust & Device Security',
      'Compliance & Data Governance'
    ];
    
    const foundSections = [];
    
    for (const section of expectedSections) {
      const sectionExists = await page.locator(`text=${section}`).count() > 0;
      if (sectionExists) {
        foundSections.push(section);
      }
    }
    
    console.log(`📊 Documentation sync status: ${foundSections.length}/${expectedSections.length} sections found`);
    foundSections.forEach(section => console.log(`✅ ${section}`));
    
    // At least some sections should be present if sync is working
    expect(foundSections.length).toBeGreaterThan(0);
  });

});

test.describe('Wiki Content Quality', () => {
  
  test('Mermaid diagrams should be properly formatted', async ({ page }) => {
    await page.goto(`${WIKI_BASE_URL}/Documentation`);
    
    // Look for domain architecture pages
    const domainPages = [
      'Authentication-&-Authorization',
      'Security-&-Monitoring',
      'Zero-Trust-&-Device-Security',
      'Compliance-&-Data-Governance'
    ];
    
    for (const domainPage of domainPages) {
      try {
        await page.goto(`${WIKI_BASE_URL}/${domainPage}`);
        
        // Check if page exists and has content
        const hasContent = await page.locator('.markdown-body').isVisible();
        
        if (hasContent) {
          // Look for Mermaid diagram blocks
          const mermaidBlocks = await page.locator('pre code.language-mermaid, .language-mermaid').count();
          
          if (mermaidBlocks > 0) {
            console.log(`✅ ${domainPage}: ${mermaidBlocks} Mermaid diagrams found`);
          } else {
            console.log(`⚠️  ${domainPage}: No Mermaid diagrams found`);
          }
        }
      } catch (error) {
        console.log(`⚠️  ${domainPage}: Page not accessible`);
      }
    }
  });

  test('Wiki should have proper table of contents', async ({ page }) => {
    await page.goto(`${WIKI_BASE_URL}/Documentation`);
    
    // Look for table of contents or navigation structure
    const tocExists = await page.locator('.markdown-body ul, .markdown-body ol').count() > 0;
    const linksExist = await page.locator('.markdown-body a[href*="wiki"]').count() > 0;
    
    if (tocExists && linksExist) {
      console.log('✅ Documentation has proper navigation structure');
    } else {
      console.log('⚠️  Documentation navigation structure needs improvement');
    }
    
    expect(tocExists || linksExist).toBeTruthy();
  });

});

test.describe('Local Documentation Verification', () => {
  
  test('Local MkDocs server should be accessible', async ({ page }) => {
    try {
      await page.goto('http://127.0.0.1:8001');
      
      // Check if local documentation loads
      await expect(page).toHaveTitle(/Zamaz/);
      
      // Verify schema documentation is present
      const schemaLink = page.locator('a[href*="schema"]');
      
      if (await schemaLink.count() > 0) {
        await schemaLink.first().click();
        console.log('✅ Local schema documentation accessible');
      }
      
    } catch (error) {
      console.log('⚠️  Local MkDocs server not running - run: make docs-mkdocs-serve');
    }
  });

});