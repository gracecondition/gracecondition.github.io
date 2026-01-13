document.addEventListener('DOMContentLoaded', function() {
    // Mobile navigation toggle
    const navToggle = document.getElementById('nav-toggle');
    const navMenu = document.getElementById('nav-menu');

    if (navToggle && navMenu) {
        navToggle.addEventListener('click', function() {
            navMenu.classList.toggle('active');

            // Animate hamburger menu
            navToggle.classList.toggle('active');
        });

        // Close mobile menu when clicking on a link
        const navLinks = navMenu.querySelectorAll('.nav-link');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                navMenu.classList.remove('active');
                navToggle.classList.remove('active');
            });
        });

        // Close mobile menu when clicking outside
        document.addEventListener('click', function(event) {
            const isClickInsideNav = navToggle.contains(event.target) || navMenu.contains(event.target);

            if (!isClickInsideNav && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
                navToggle.classList.remove('active');
            }
        });
    }

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Add reading progress bar for blog posts
    if (document.querySelector('.single-post')) {
        const progressBar = document.createElement('div');
        progressBar.className = 'reading-progress';
        progressBar.innerHTML = '<div class="reading-progress-fill"></div>';
        document.body.appendChild(progressBar);

        const progressFill = progressBar.querySelector('.reading-progress-fill');

        window.addEventListener('scroll', function() {
            const article = document.querySelector('.post-body');
            if (!article) return;

            const articleTop = article.offsetTop;
            const articleHeight = article.offsetHeight;
            const viewportHeight = window.innerHeight;
            const scrollTop = window.scrollY;

            const start = articleTop - viewportHeight / 2;
            const end = articleTop + articleHeight - viewportHeight / 2;

            if (scrollTop >= start && scrollTop <= end) {
                const progress = (scrollTop - start) / (end - start);
                progressFill.style.width = Math.min(100, Math.max(0, progress * 100)) + '%';
            } else if (scrollTop < start) {
                progressFill.style.width = '0%';
            } else {
                progressFill.style.width = '100%';
            }
        });
    }

    // Add copy button to code blocks
    document.querySelectorAll('pre code').forEach((block) => {
        const button = document.createElement('button');
        button.className = 'copy-code-button';
        button.textContent = 'Copy';
        button.addEventListener('click', () => {
            navigator.clipboard.writeText(block.textContent).then(() => {
                button.textContent = 'Copied!';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            }).catch(() => {
                button.textContent = 'Failed';
                setTimeout(() => {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block-wrapper';

        const pre = block.parentNode;
        const highlight = pre ? pre.parentNode : null;
        let container = pre;

        if (highlight && (highlight.classList.contains('highlight') || highlight.classList.contains('chroma'))) {
            container = highlight;
        }

        if (!container || (container.parentNode && container.parentNode.classList.contains('code-block-wrapper'))) {
            return;
        }

        container.parentNode.insertBefore(wrapper, container);
        wrapper.appendChild(button);
        wrapper.appendChild(container);
    });

    // Sidebar search and filter functionality
    if (document.querySelector('.sidebar')) {
        initializeSidebarFeatures();
    }

    // BULLETPROOF TOC - Execute immediately, no delays, no failures
    if (document.querySelector('.toc-sidebar')) {
        forceTOCGeneration();

        // Also try on various events as backup
        document.addEventListener('DOMContentLoaded', forceTOCGeneration);
        window.addEventListener('load', forceTOCGeneration);

        // Ultra-aggressive fallback
        setTimeout(forceTOCGeneration, 50);
        setTimeout(forceTOCGeneration, 200);
        setTimeout(forceTOCGeneration, 500);
        setTimeout(forceTOCGeneration, 1000);
    }

    // Initialize image lightbox
    initializeImageLightbox();

    // Initialize mobile Mermaid diagrams
    initializeMobileMermaid();
});

function initializeSidebarFeatures() {
    initializeBulletproofSearch();
    initializeCategoryFilters();
    initializeShowMoreButtons();
}

function initializeBulletproofSearch() {
    const searchInput = document.getElementById('search-input-robust');
    const searchClear = document.getElementById('search-clear-robust');
    const searchCount = document.getElementById('search-count-robust');
    const searchList = document.getElementById('search-list-robust');

    console.log('🚀 INITIALIZING BULLETPROOF SEARCH');
    console.log('Elements found:', { searchInput, searchClear, searchCount, searchList });

    if (!searchInput || !searchList) {
        console.error('❌ Required search elements not found!');
        return;
    }

    // Collect all posts for search
    const allPosts = [];
    document.querySelectorAll('.recent-post-item, .category-post-item, .ctf-competition-item').forEach(item => {
        const titleElement = item.querySelector('.recent-post-title, .category-post-title, .ctf-competition-name');
        const excerptElement = item.querySelector('.recent-post-excerpt');
        const linkElement = item.querySelector('a');

        if (titleElement && linkElement) {
            allPosts.push({
                title: titleElement.textContent.trim(),
                excerpt: excerptElement ? excerptElement.textContent.trim() : '',
                link: linkElement.href,
                element: item
            });
        }
    });

    console.log(`📚 Found ${allPosts.length} posts for search`);

    function performSearch(query) {
        const trimmedQuery = query.trim().toLowerCase();
        const searchResults = document.getElementById('search-results-robust');

        if (!trimmedQuery) {
            // Hide search results completely when not searching
            searchResults.style.display = 'none';
            searchClear.style.display = 'none';
            return;
        }

        // Show search results container and clear button
        searchResults.style.display = 'block';
        searchClear.style.display = 'block';

        // Filter posts
        const results = allPosts.filter(post =>
            post.title.toLowerCase().includes(trimmedQuery) ||
            post.excerpt.toLowerCase().includes(trimmedQuery)
        );

        console.log(`🔍 Search for "${trimmedQuery}" found ${results.length} results`);

        // Display results (no demo items)
        if (results.length === 0) {
            searchList.innerHTML = `
                <div class="search-result-item-robust">
                    <div class="search-result-title-robust">No results found</div>
                    <div class="search-result-excerpt-robust">Try different keywords or check spelling</div>
                </div>
            `;
            searchCount.textContent = `No results for "${query}"`;
        } else {
            const html = results.map(post => `
                <div class="search-result-item-robust" onclick="window.location.href='${post.link}'">
                    <div class="search-result-title-robust">${highlightTerm(post.title, trimmedQuery)}</div>
                    <div class="search-result-excerpt-robust">${highlightTerm(post.excerpt, trimmedQuery)}</div>
                </div>
            `).join('');

            searchList.innerHTML = html;
            searchCount.textContent = `Found ${results.length} result${results.length !== 1 ? 's' : ''} for "${query}"`;
        }
    }

    function highlightTerm(text, term) {
        if (!text || !term) return text;
        const regex = new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return text.replace(regex, '<strong style="background: var(--accent-color); color: white; padding: 1px 3px; border-radius: 2px;">$1</strong>');
    }

    // Event listeners
    searchInput.addEventListener('input', function() {
        const sidebar = document.querySelector('.sidebar');

        if (this.value.trim().length > 0) {
            // Add expanded class when typing
            if (sidebar) {
                sidebar.classList.add('search-expanded');
            }
        } else {
            // Remove expanded class when no input
            if (sidebar) {
                sidebar.classList.remove('search-expanded');
            }
        }

        performSearch(this.value);
    });

    searchClear.addEventListener('click', function() {
        const sidebar = document.querySelector('.sidebar');

        searchInput.value = '';
        if (sidebar) {
            sidebar.classList.remove('search-expanded');
        }
        performSearch('');
        searchInput.focus();
    });

    // Initial state - hide search results
    document.getElementById('search-results-robust').style.display = 'none';

    // Add scrolling class management for better scrollbar visibility
    let scrollTimeout;
    const searchScrollable = document.querySelector('.search-results-scrollable');
    if (searchScrollable) {
        searchScrollable.addEventListener('scroll', function() {
            this.classList.add('scrolling');
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(() => {
                this.classList.remove('scrolling');
            }, 1000);
        });
    }

    console.log('✅ BULLETPROOF SEARCH INITIALIZED');
}

function initializeAppleStyleSearch() {
    const searchInput = document.getElementById('search-input');
    const searchClear = document.getElementById('search-clear');
    const searchDropdown = document.getElementById('search-dropdown');
    const searchResultsList = document.querySelector('.search-results-list');
    const searchResultsCount = document.querySelector('.search-results-count');

    // Collect all posts for search
    const allPosts = [];
    document.querySelectorAll('.recent-post-item, .category-post-item').forEach(item => {
        const titleElement = item.querySelector('.recent-post-title, .category-post-title');
        const excerptElement = item.querySelector('.recent-post-excerpt');
        const linkElement = item.querySelector('a');
        const categoryElement = item.querySelector('.recent-post-category');
        const dateElement = item.querySelector('.recent-post-date, .category-post-date');

        if (titleElement && linkElement) {
            allPosts.push({
                title: titleElement.textContent.trim(),
                excerpt: excerptElement ? excerptElement.textContent.trim() : '',
                link: linkElement.href,
                category: item.dataset.category || 'security',
                categoryIcon: categoryElement ? categoryElement.textContent.trim() : '🔐',
                date: dateElement ? dateElement.textContent.trim() : '',
                element: item
            });
        }
    });

    let currentHighlighted = -1;
    let searchResults = [];

    function performSearch(query) {
        const trimmedQuery = query.trim();

        if (!trimmedQuery) {
            hideSearchDropdown();
            return;
        }

        searchResults = allPosts.filter(post => {
            return post.title.toLowerCase().includes(trimmedQuery.toLowerCase()) ||
                   post.excerpt.toLowerCase().includes(trimmedQuery.toLowerCase());
        });

        displaySearchResults(searchResults, trimmedQuery);
        showSearchDropdown();
    }

    function displaySearchResults(results, query) {
        let content = '';

        if (results.length === 0) {
            content = `
                <div class="search-no-results">
                    <div class="search-no-results-title">No results found for "${query}"</div>
                    <div class="search-no-results-subtitle">Try adjusting your search terms</div>
                </div>
            `;
            searchResultsCount.textContent = '0 results';
        } else {
            content = results.map((post, index) => `
                <div class="search-result-item" data-index="${index}">
                    <a href="${post.link}" class="search-result-link">
                        <div class="search-result-header">
                            <div class="search-result-icon">${post.categoryIcon}</div>
                            <div class="search-result-content">
                                <div class="search-result-title">${highlightSearchTerm(post.title, query)}</div>
                                <div class="search-result-meta">
                                    <span class="search-result-category">${post.category}</span>
                                    <span class="search-result-date">${post.date}</span>
                                </div>
                                ${post.excerpt ? `<div class="search-result-excerpt">${highlightSearchTerm(post.excerpt, query)}</div>` : ''}
                            </div>
                        </div>
                    </a>
                </div>
            `).join('');

            searchResultsCount.textContent = `${results.length} result${results.length !== 1 ? 's' : ''}`;
        }

        // Add dummy items to ensure scrolling is always possible
        for (let i = 0; i < 10; i++) {
            content += `
                <div class="search-result-item" style="opacity: 0.3; pointer-events: none;">
                    <div class="search-result-header">
                        <div class="search-result-icon">📄</div>
                        <div class="search-result-content">
                            <div class="search-result-title">Scroll test item ${i + 1}</div>
                            <div class="search-result-meta">
                                <span class="search-result-category">test</span>
                                <span class="search-result-date">Today</span>
                            </div>
                            <div class="search-result-excerpt">This is a dummy item to test scrolling functionality</div>
                        </div>
                    </div>
                </div>
            `;
        }

        searchResultsList.innerHTML = content;
        currentHighlighted = -1;
    }

    function highlightSearchTerm(text, query) {
        if (!text || !query) return text;
        const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        return text.replace(regex, '<span class="search-highlight">$1</span>');
    }

    function showSearchDropdown() {
        searchDropdown.style.display = 'block';
        searchDropdown.style.animation = 'none';
        searchDropdown.offsetHeight; // Force reflow
        searchDropdown.style.animation = 'fadeIn 0.15s ease-out';
    }

    function hideSearchDropdown() {
        searchDropdown.style.display = 'none';
        currentHighlighted = -1;
    }

    function highlightResult(index) {
        const items = searchResultsList.querySelectorAll('.search-result-item');
        items.forEach((item, i) => {
            item.classList.toggle('highlighted', i === index);
        });
    }

    // Event listeners
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchContainer = document.querySelector('.search-container-robust');

            if (this.value.trim().length > 0) {
                // Add expanded class when typing
                if (searchContainer) {
                    searchContainer.classList.add('search-expanded');
                }
            } else {
                // Remove expanded class when no input
                if (searchContainer) {
                    searchContainer.classList.remove('search-expanded');
                }
            }

            performSearch(this.value);
        });

        searchInput.addEventListener('keydown', function(e) {
            const items = searchResultsList.querySelectorAll('.search-result-item');

            switch(e.key) {
                case 'ArrowDown':
                    e.preventDefault();
                    currentHighlighted = Math.min(currentHighlighted + 1, items.length - 1);
                    highlightResult(currentHighlighted);
                    break;

                case 'ArrowUp':
                    e.preventDefault();
                    currentHighlighted = Math.max(currentHighlighted - 1, -1);
                    highlightResult(currentHighlighted);
                    break;

                case 'Enter':
                    e.preventDefault();
                    if (currentHighlighted >= 0 && items[currentHighlighted]) {
                        const link = items[currentHighlighted].querySelector('a');
                        if (link) window.location.href = link.href;
                    }
                    break;

                case 'Escape':
                    hideSearchDropdown();
                    this.blur();
                    break;
            }
        });

        searchInput.addEventListener('focus', function() {
            if (this.value.trim() && searchResults.length > 0) {
                showSearchDropdown();
            }
        });
    }

    if (searchClear) {
        searchClear.addEventListener('click', function() {
            searchInput.value = '';
            hideSearchDropdown();
            searchInput.focus();
        });
    }

    // Click outside to close
    document.addEventListener('click', function(e) {
        if (!searchInput.contains(e.target) && !searchDropdown.contains(e.target)) {
            hideSearchDropdown();
        }
    });

    // Add CSS animation
    if (!document.getElementById('search-animations')) {
        const style = document.createElement('style');
        style.id = 'search-animations';
        style.textContent = `
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(-8px); }
                to { opacity: 1; transform: translateY(0); }
            }
        `;
        document.head.appendChild(style);
    }
}

function initializeCategoryFilters() {
    const categoryFilters = document.querySelectorAll('.category-filter');
    const searchInput = document.getElementById('search-input');

    categoryFilters.forEach(filter => {
        filter.addEventListener('click', function() {
            // Clear search when switching categories
            if (searchInput && searchInput.value.trim()) {
                searchInput.value = '';
                const searchDropdown = document.getElementById('search-dropdown');
                if (searchDropdown) searchDropdown.style.display = 'none';
            }

            categoryFilters.forEach(f => f.classList.remove('active'));
            this.classList.add('active');

            const category = this.dataset.category;
            filterContent('', category);
        });
    });
}

function initializeShowMoreButtons() {
    const showMoreButtons = document.querySelectorAll('.show-more-btn');
    showMoreButtons.forEach(btn => {
        btn.addEventListener('click', function() {
            const category = this.dataset.category;
            const categoryGroup = this.closest('.category-group');
            const hiddenItems = categoryGroup.querySelectorAll('.category-post-item[style*="display: none"]');

            hiddenItems.forEach((item, index) => {
                if (index < 5) {
                    item.style.display = 'block';
                }
            });

            const stillHidden = categoryGroup.querySelectorAll('.category-post-item[style*="display: none"]');
            if (stillHidden.length === 0) {
                this.style.display = 'none';
            } else {
                this.textContent = `Show ${stillHidden.length} more...`;
            }
        });
    });
}

function filterContent(query, category) {
    const postItems = document.querySelectorAll('.recent-post-item, .category-post-item');
    const categoryGroups = document.querySelectorAll('.category-group');

    postItems.forEach(item => {
        const title = item.querySelector('.recent-post-title, .category-post-title')?.textContent.toLowerCase() || '';
        const excerpt = item.querySelector('.recent-post-excerpt')?.textContent.toLowerCase() || '';
        const itemCategory = item.dataset.category || '';

        const matchesSearch = !query || title.includes(query) || excerpt.includes(query);
        const matchesCategory = category === 'all' || itemCategory === category;

        if (matchesSearch && matchesCategory) {
            item.style.display = 'block';
        } else {
            item.style.display = 'none';
        }
    });

    // Handle category group visibility
    categoryGroups.forEach(group => {
        const visibleItems = group.querySelectorAll('.category-post-item[style="display: block"], .category-post-item:not([style*="display: none"])');
        const groupCategory = group.querySelector('.category-group-title')?.textContent.toLowerCase().includes(category.toLowerCase());

        if (category === 'all' || groupCategory || visibleItems.length > 0) {
            group.style.display = 'block';
        } else {
            group.style.display = 'none';
        }
    });
}

function getActiveCategory() {
    const activeFilter = document.querySelector('.category-filter.active');
    return activeFilter ? activeFilter.dataset.category : 'all';
}

function forceTOCGeneration() {
    const tocNav = document.getElementById('toc-nav');
    if (!tocNav) return;

    // Check if Hugo already generated TOC (server-side)
    const existingTOC = tocNav.querySelector('ul, nav');
    if (existingTOC && !tocNav.querySelector('.toc-loading')) {
        console.log('✅ Server-side TOC found, enhancing with reactive features...');
        // TOC already exists from Hugo, just initialize interactive features
        try {
            initializeReadingProgress();
            initializeSectionHighlighting();
        } catch (e) {
            console.log('TOC enhancement failed:', e);
        }
        return;
    }

    // Skip if already generated by JavaScript
    if (tocNav.querySelector('ul:not(.toc-loading *)')) return;

    console.log('FORCE GENERATING TOC...');

    // Try multiple content selectors
    let postContent = document.getElementById('post-content') ||
                     document.querySelector('.post-body') ||
                     document.querySelector('.ctf-content') ||
                     document.querySelector('article') ||
                     document.querySelector('main') ||
                     document.querySelector('.single-post');

    console.log('Found content element:', postContent);

    if (!postContent) {
        tocNav.innerHTML = '<div class="toc-loading">❌ Content element not found</div>';
        return;
    }

    // Wait a bit for content to load, then generate
    let attempts = 0;
    const generateTOC = () => {
        attempts++;
        console.log(`TOC Generation attempt ${attempts}`);

        const headings = postContent.querySelectorAll('h1, h2, h3, h4, h5, h6');
        console.log(`Found ${headings.length} headings:`, Array.from(headings).map(h => h.textContent));

        if (headings.length === 0 && attempts < 10) {
            tocNav.innerHTML = `<div class="toc-loading">⏳ Searching for headings... (${attempts}/10)</div>`;
            setTimeout(generateTOC, 100);
            return;
        }

        if (headings.length === 0) {
            // Generate fake TOC to test functionality
            tocNav.innerHTML = `
                <ul>
                    <li><a href="#" class="toc-level-1">🔍 No headings detected</a></li>
                    <li><a href="#" class="toc-level-2">📄 Content: ${postContent.textContent.trim().substring(0, 50)}...</a></li>
                    <li><a href="#" class="toc-level-2">📊 Length: ${postContent.textContent.length} chars</a></li>
                    <li><a href="#" class="toc-level-2">🏷️ Tag: ${postContent.tagName}</a></li>
                </ul>
            `;
            return;
        }

        // Generate real TOC
        const tocList = document.createElement('ul');

        headings.forEach((heading, index) => {
            const level = parseInt(heading.tagName.charAt(1));
            const text = heading.textContent.trim();
            const id = heading.id || `toc-heading-${index}`;

            if (!heading.id) {
                heading.id = id;
            }

            const listItem = document.createElement('li');
            const link = document.createElement('a');

            link.href = `#${id}`;
            link.textContent = `${level === 1 ? '📖' : level === 2 ? '📝' : '📌'} ${text}`;
            link.className = `toc-level-${level}`;

            link.addEventListener('click', (e) => {
                e.preventDefault();
                heading.scrollIntoView({ behavior: 'smooth', block: 'start' });

                tocNav.querySelectorAll('a').forEach(a => a.classList.remove('active'));
                link.classList.add('active');
            });

            listItem.appendChild(link);
            tocList.appendChild(listItem);
        });

        tocNav.innerHTML = '';
        tocNav.appendChild(tocList);

        console.log('✅ TOC Generated successfully!');

        // Initialize additional features
        try {
            initializeReadingProgress();
            initializeSectionHighlighting();
        } catch (e) {
            console.log('TOC extras failed:', e);
        }
    };

    generateTOC();
}

function initializeTOC() {
    console.log('Initializing TOC...');
    const tocNav = document.getElementById('toc-nav');
    const postContent = document.getElementById('post-content') || document.querySelector('.post-body');
    console.log('TOC elements:', { tocNav, postContent });
    console.log('Post content children count:', postContent ? postContent.children.length : 0);
    console.log('Post content HTML length:', postContent ? postContent.innerHTML.length : 0);

    if (!tocNav) {
        console.log('TOC nav not found, skipping TOC generation');
        return;
    }

    if (!postContent) {
        console.log('Post content not found, showing fallback message');
        tocNav.innerHTML = '<div class="toc-loading">No content found</div>';
        return;
    }

    // Check if content is actually loaded (not just empty div)
    if (postContent.children.length === 0 && postContent.textContent.trim().length === 0) {
        console.log('Post content is empty, content may still be loading');
        tocNav.innerHTML = '<div class="toc-loading">Content still loading...</div>';
        return;
    }

    // Generate table of contents
    console.log('Calling generateTOC...');
    generateTOC(postContent, tocNav);

    // Initialize reading progress
    initializeReadingProgress();

    // Initialize section highlighting
    initializeSectionHighlighting();
}

function generateTOC(content, tocContainer) {
    console.log('Generating TOC for content:', content);

    try {
        const headings = content.querySelectorAll('h1, h2, h3, h4, h5, h6');
        console.log('Found headings:', headings.length, headings);

        if (headings.length === 0) {
            console.log('No headings found, showing "No sections found"');
            tocContainer.innerHTML = '<div class="toc-loading">No sections found</div>';
            return;
        }

        console.log('Creating TOC list...');
        const tocList = document.createElement('ul');

        headings.forEach((heading, index) => {
            try {
                console.log(`Processing heading ${index + 1}/${headings.length}:`, heading.textContent);
                const level = parseInt(heading.tagName.charAt(1));
                const headingText = heading.textContent.trim();
                const id = heading.id || `heading-${index}`;

                // Create ID if it doesn't exist
                if (!heading.id) {
                    heading.id = id;
                }

                const listItem = document.createElement('li');
                const link = document.createElement('a');

                link.href = `#${id}`;
                link.textContent = headingText;
                link.dataset.target = id;
                link.className = `toc-level-${level}`;

                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    heading.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });

                    // Update active state
                    tocContainer.querySelectorAll('a').forEach(a => a.classList.remove('active'));
                    link.classList.add('active');
                });

                listItem.appendChild(link);
                tocList.appendChild(listItem);
            } catch (headingError) {
                console.error(`Error processing heading ${index}:`, headingError);
            }
        });

        tocContainer.innerHTML = '';
        tocContainer.appendChild(tocList);
        console.log('TOC generation completed successfully');
    } catch (error) {
        console.error('Error generating TOC:', error);
        tocContainer.innerHTML = '<div class="toc-loading">Error generating table of contents</div>';
    }
}

function initializeReadingProgress() {
    const progressFill = document.getElementById('progress-fill');
    const progressPercentage = document.getElementById('progress-percentage');
    const postContent = document.getElementById('post-content');

    if (!progressFill || !progressPercentage || !postContent) return;

    function updateProgress() {
        const contentRect = postContent.getBoundingClientRect();
        const contentTop = contentRect.top + window.pageYOffset;
        const contentHeight = contentRect.height;
        const windowHeight = window.innerHeight;
        const scrollTop = window.pageYOffset;

        const startReading = contentTop - windowHeight / 3;
        const finishReading = contentTop + contentHeight - windowHeight / 3;

        let progress = 0;

        if (scrollTop >= startReading && scrollTop <= finishReading) {
            progress = (scrollTop - startReading) / (finishReading - startReading);
        } else if (scrollTop > finishReading) {
            progress = 1;
        }

        const percentage = Math.round(Math.min(100, Math.max(0, progress * 100)));
        progressFill.style.width = percentage + '%';
        progressPercentage.textContent = percentage + '%';
    }

    window.addEventListener('scroll', updateProgress);
    updateProgress();
}

function initializeSectionHighlighting() {
    console.log('🎯 Initializing section highlighting...');

    // Try multiple selectors to find TOC links and headings
    const tocNav = document.getElementById('toc-nav');
    if (!tocNav) {
        console.log('❌ TOC nav not found for highlighting');
        return;
    }

    function updateHighlighting() {
        const tocLinks = tocNav.querySelectorAll('a');

        // Find all headings in the post content
        let postContent = document.getElementById('post-content') ||
                         document.querySelector('.post-body') ||
                         document.querySelector('article') ||
                         document.querySelector('.single-post');

        if (!postContent) {
            console.log('❌ Post content not found for highlighting');
            return;
        }

        const headings = Array.from(postContent.querySelectorAll('h1, h2, h3, h4, h5, h6'));

        if (tocLinks.length === 0 || headings.length === 0) {
            console.log('⚠️ No TOC links or headings found');
            return;
        }

        // Find the current section based on scroll position
        let currentSection = null;
        const scrollPosition = window.scrollY + 150; // Offset for better UX

        for (let i = headings.length - 1; i >= 0; i--) {
            const heading = headings[i];
            const headingTop = heading.offsetTop;

            if (scrollPosition >= headingTop) {
                currentSection = heading.id;
                break;
            }
        }

        // Update active states
        tocLinks.forEach(link => {
            link.classList.remove('active');
            const href = link.getAttribute('href');

            if (href && currentSection && href === `#${currentSection}`) {
                link.classList.add('active');

                // Scroll the TOC to make the active link visible
                const tocContent = tocNav.closest('.toc-content');
                if (tocContent) {
                    const linkRect = link.getBoundingClientRect();
                    const tocRect = tocContent.getBoundingClientRect();

                    if (linkRect.top < tocRect.top || linkRect.bottom > tocRect.bottom) {
                        link.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                    }
                }
            }
        });
    }

    // Listen for scroll events with throttling for performance
    let scrollTimeout;
    window.addEventListener('scroll', function() {
        if (scrollTimeout) {
            clearTimeout(scrollTimeout);
        }
        scrollTimeout = setTimeout(updateHighlighting, 50);
    });

    // Initial highlight
    updateHighlighting();

    console.log('✅ Section highlighting initialized');
}

function initializeImageLightbox() {
    // Create lightbox modal element
    const lightbox = document.createElement('div');
    lightbox.className = 'image-lightbox';
    lightbox.innerHTML = `
        <div class="image-lightbox-close"></div>
        <img src="" alt="">
    `;
    document.body.appendChild(lightbox);

    const lightboxImg = lightbox.querySelector('img');
    const closeBtn = lightbox.querySelector('.image-lightbox-close');

    // Find all images in post body (excluding icons and small images)
    const images = document.querySelectorAll('.post-body img, article img, .single-post img');

    images.forEach(img => {
        // Skip if image is very small (likely an icon)
        if (img.width < 100 && img.height < 100) return;

        // Add click event to open lightbox
        img.addEventListener('click', function(e) {
            e.preventDefault();
            lightboxImg.src = this.src;
            lightboxImg.alt = this.alt || '';
            lightbox.classList.add('active');
            document.body.style.overflow = 'hidden'; // Prevent scrolling
        });
    });

    // Close lightbox on background click
    lightbox.addEventListener('click', function(e) {
        if (e.target === lightbox || e.target === lightboxImg) {
            closeLightbox();
        }
    });

    // Close lightbox on close button click
    closeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        closeLightbox();
    });

    // Close lightbox on ESC key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && lightbox.classList.contains('active')) {
            closeLightbox();
        }
    });

    function closeLightbox() {
        lightbox.classList.remove('active');
        document.body.style.overflow = ''; // Re-enable scrolling
        setTimeout(() => {
            lightboxImg.src = '';
        }, 200);
    }
}

// Mobile Mermaid handler with fallback support
function initializeMobileMermaid() {
    const isMobile = window.innerWidth <= 768;

    if (!isMobile) {
        console.log('Desktop - using normal Mermaid rendering');
        return;
    }

    console.log('📱 Mobile detected - checking for fallback SVGs');

    setTimeout(() => {
        const wrappers = document.querySelectorAll('.mermaid-wrapper');

        if (wrappers.length === 0) {
            console.log('No Mermaid diagrams found');
            return;
        }

        console.log(`Found ${wrappers.length} Mermaid diagram(s)`);

        wrappers.forEach((wrapper, index) => {
            const fallbackPath = wrapper.dataset.fallback;

            // Skip if no fallback or already replaced
            if (!fallbackPath || wrapper.dataset.replaced === 'true') {
                console.log(`Diagram ${index}: No fallback specified, using normal rendering`);
                return;
            }

            console.log(`Diagram ${index}: Using fallback ${fallbackPath}`);

            const mermaidDiv = wrapper.querySelector('.mermaid');
            if (!mermaidDiv) return;

            // Create image element
            const img = document.createElement('img');
            img.src = fallbackPath;
            img.alt = 'Diagram';
            img.style.width = '100%';
            img.style.height = 'auto';
            img.style.display = 'block';
            img.style.margin = '0';
            img.style.backgroundColor = '#0a0a0a';
            img.style.padding = '16px';
            img.style.borderRadius = '8px';
            img.style.boxSizing = 'border-box';

            // Handle load/error
            img.onload = () => {
                console.log(`✅ Diagram ${index}: Fallback loaded successfully`);
            };

            img.onerror = () => {
                console.error(`❌ Diagram ${index}: Failed to load fallback from ${fallbackPath}`);
                // Show error message
                const error = document.createElement('div');
                error.textContent = '⚠️ Diagram failed to load. Please view on desktop.';
                error.style.cssText = 'padding:16px;background:rgba(255,59,48,0.1);border:1px solid rgba(255,59,48,0.3);border-radius:8px;color:#ff3b30;text-align:center;';
                mermaidDiv.innerHTML = '';
                mermaidDiv.appendChild(error);
                return;
            };

            // Replace Mermaid with image
            mermaidDiv.innerHTML = '';
            mermaidDiv.appendChild(img);

            // Add tap hint
            const hint = document.createElement('div');
            hint.style.cssText = `
                text-align: center;
                font-size: 11px;
                color: #666;
                margin-top: 8px;
                font-style: italic;
            `;
            hint.textContent = 'Tap to view full size';
            mermaidDiv.appendChild(hint);

            // Make clickable for lightbox
            img.style.cursor = 'zoom-in';
            img.addEventListener('click', () => {
                const lightbox = document.querySelector('.image-lightbox');
                if (lightbox) {
                    const lightboxImg = lightbox.querySelector('img');
                    lightboxImg.src = fallbackPath;
                    lightbox.classList.add('active');
                    document.body.style.overflow = 'hidden';
                }
            });

            // Mark as replaced
            wrapper.dataset.replaced = 'true';
        });
    }, 500);
}
