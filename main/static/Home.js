document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const walletDropdown = document.getElementById('wallet-dropdown');
    const walletMenu = document.getElementById('wallet-menu');
    const dropdownToggle = document.getElementById('dropdown-toggle');
    const dropdownMenu = document.getElementById('dropdown-menu');
    const searchInput = document.getElementById('search-input');
    const suggestions = document.getElementById('suggestions');
    const marketRows = document.getElementById('market-rows');
    const viewMoreBtn = document.getElementById('view-more-btn');
    const chartCanvas = document.getElementById('price-chart').getContext('2d');
    const coinLogoImg = document.getElementById('coin-logo'); 
    const coinNameSpan = document.getElementById('coin-name');
     const showAllBtn = document.getElementById('show-all-btn'); 

    let currentChart = null;

    // API Configuration
    const apiBaseUrl = 'https://api.coingecko.com/api/v3/coins';
    let coinsData = [];
    let displayedCoins = 5;
     let selectedCoin = null; // Tracks the currently selected coin

    // Event Listeners for Dropdown Menus
    if (walletDropdown && walletMenu) {
        walletDropdown.addEventListener('click', () => {
            walletMenu.classList.toggle('visible');
            console.log('Wallet Dropdown Toggled');
        });
    }

    if (dropdownToggle && dropdownMenu) {
        dropdownToggle.addEventListener('click', () => {
            dropdownMenu.classList.toggle('visible');
            console.log('Dropdown Menu Toggled');
        });
    }

    // Close Dropdowns When Clicking Outside
    document.addEventListener('click', (event) => {
        if (walletDropdown && walletMenu) {
            if (!walletDropdown.contains(event.target) && !walletMenu.contains(event.target)) {
                walletMenu.classList.remove('visible');
                console.log('Wallet Menu Hidden');
            }
        }
        if (dropdownToggle && dropdownMenu) {
            if (!dropdownToggle.contains(event.target) && !dropdownMenu.contains(event.target)) {
                dropdownMenu.classList.remove('visible');
                console.log('Dropdown Menu Hidden');
            }
        }
    });


    // Fetch Coin Market Data
    async function fetchCoinData() {
        try {
            const response = await fetch(`${apiBaseUrl}/markets?vs_currency=inr&order=market_cap_desc&per_page=250&page=1&sparkline=false`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            console.log('Fetched Coin Data:', data);
            if (!Array.isArray(data)) throw new TypeError('Response data is not an array');
            coinsData = data;
            updateDisplay();
            // Optionally, set initial chart to the first coin
           if (coinsData.length > 0 && !selectedCoin) {
                renderLineChart(coinsData[0].id, coinsData[0].name, coinsData[0].image);
            }
        } catch (error) {
            console.error('Error fetching coin data:', error);
        }
    }

    // Update the Market Table Display
    function updateDisplay() {
          const coinsToDisplay = selectedCoin ? [selectedCoin] : coinsData.slice(0, displayedCoins);
        populateMarketTable(coinsToDisplay);
         setupSearchSuggestions();
         toggleShowAllButton();
    }

    // Populate the Market Table with Coin Data
    function populateMarketTable(coins) {
        console.log('Populating market table with coins:', coins);
         marketRows.innerHTML = '';
        coins.forEach(coin => {
            console.log('Adding coin:', coin.name);
            const row = document.createElement('div');
            row.classList.add('table-row');
             const changeClass = coin.price_change_percentage_24h >= 0 ? 'green' : 'red';
            row.innerHTML = `
                <span class="name" data-coin-id="${coin.id}">
                    <img src="${coin.image}" alt="${coin.name}" class="coin-image">
                    ${coin.name}
                </span>
                <span class="price">
                    ₹${formatNumber(coin.current_price)}
                    <br>
                    <span class="change ${changeClass}">${coin.price_change_percentage_24h.toFixed(2)}%</span>
                </span>
                <span class="cap">₹${formatNumber(coin.market_cap)}</span>
            `;
           // Add Click Event Listener to Render Chart with Selected Coin
             row.addEventListener('click', () => {
                console.log(`Coin clicked: ${coin.name}`);
                 if (selectedCoin && selectedCoin.id === coin.id) {
                    // If the same coin is clicked again, deselect it
                    selectedCoin = null;
                } else {
                    selectedCoin = coin;
                }
                updateDisplay();
                if (selectedCoin) {
                    renderLineChart(selectedCoin.id, selectedCoin.name, selectedCoin.image);
                } else {
                    // If deselected, optionally reset to the first coin or keep the current chart
                    // Here, we'll keep the current chart as is
                 }
             });
            marketRows.appendChild(row);
        });
    }

    // Format Numbers with Commas and Fixed Decimal Places
    function formatNumber(num) {
        return num.toLocaleString(undefined, { maximumFractionDigits: 2 });
    }

    // Handle "View More/View Less" Functionality
    viewMoreBtn.addEventListener('click', (e) => {
        e.preventDefault();
        console.log('View More Button Clicked');
        if (viewMoreBtn.textContent === 'View More') {
            displayedCoins = coinsData.length;
            viewMoreBtn.textContent = 'View Less';
        } else {
            displayedCoins = 5;
            viewMoreBtn.textContent = 'View More';
        }
        updateDisplay();
    });

   // Setup Search Suggestions Based on User Input
    function setupSearchSuggestions() {
         searchInput.addEventListener('input', () => {
            const value = searchInput.value.toLowerCase();
              suggestions.innerHTML = '';
           if (value) {
                 const filtered = coinsData.filter(coin => coin.name.toLowerCase().includes(value));
                if (filtered.length > 0) {
                      suggestions.style.display = 'block';
                    filtered.forEach(coin => {
                           const li = document.createElement('li');
                            li.classList.add('suggestion-item'); // Added for better CSS targeting
                             li.innerHTML = `
                               <img src="${coin.image}" alt="${coin.name} Logo" class="suggestion-logo">
                                <span>${coin.name}</span>
                         `;
                            li.addEventListener('click', () => {
                                 searchInput.value = coin.name;
                                 suggestions.style.display = 'none';
                                 selectedCoin = coin;
                                  updateDisplay();
                                  renderLineChart(coin.id, coin.name, coin.image);
                         });
                            suggestions.appendChild(li);
                       });
                } else {
                    suggestions.style.display = 'none';
               }
            } else {
                suggestions.style.display = 'none';
            }
       });

        // Hide suggestions when clicking outside
       document.addEventListener('click', (event) => {
            if (!searchInput.contains(event.target) && !suggestions.contains(event.target)) {
                suggestions.style.display = 'none';
            }
        });
    }

      // Toggle Visibility of "Show All" Button
    function toggleShowAllButton() {
         if (selectedCoin) {
             if (showAllBtn) {
                showAllBtn.style.display = 'block';
            }
        } else {
            if (showAllBtn) {
                showAllBtn.style.display = 'none';
            }
        }
    }
   // "Show All" Button Click Handler
    if (showAllBtn) {
        showAllBtn.addEventListener('click', (e) => {
            e.preventDefault();
            console.log('Show All Button Clicked');
             selectedCoin = null;
             updateDisplay();
            // Optionally, reset the chart to the first coin or keep the current chart
             if (coinsData.length > 0) {
                renderLineChart(coinsData[0].id, coinsData[0].name, coinsData[0].image);
            }
        });
    }

    // Fetch Historical Price Data for a Specific Coin
    async function fetchHistoricalData(coinId, vsCurrency) {
        try {
            const response = await fetch(`${apiBaseUrl}/${coinId}/market_chart?vs_currency=${vsCurrency}&days=7`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();

           // Sample data to reduce the number of points (e.g., one point every hour)
            const sampledData = data.prices.filter((_, index) => index % 4 === 0); // Adjust the modulus as needed

           return sampledData.map(price => ({
                x: price[0],
                y: price[1]
            }));
        } catch (error) {
            console.error('Error fetching historical data:', error);
            return [];
        }
    }

     // Render the Line Chart with the Selected Coin's Data and Logo
   async function renderLineChart(coinId = 'bitcoin', coinName = 'Bitcoin', coinLogo = '') {
         console.log(`Rendering chart for: ${coinName}`);
        const vsCurrency = 'inr';
        const prices = await fetchHistoricalData(coinId, vsCurrency);

       // Destroy the existing chart if it exists
         if (currentChart) {
            currentChart.destroy();
             console.log('Existing chart destroyed');
        }

         // Update the coin logo image and name
        if (coinLogoImg) {
            coinLogoImg.src = coinLogo;
            coinLogoImg.alt = `${coinName} Logo`;
           if (coinNameSpan) {
                coinNameSpan.textContent = coinName; // Update coin name display
            }
        }

       // Create the Chart
        currentChart = new Chart(chartCanvas, {
            type: 'line',
            data: {
                datasets: [{
                    label: `${coinName} Price Chart`,
                     data: prices,
                    borderColor: 'gold',
                     backgroundColor: '#03322c79',
                   pointBackgroundColor: 'black',
                    pointBorderColor: 'green',
                    pointRadius: 5,
                    pointHoverRadius: 8,
                    hitRadius: 10,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                }]
            },
             options: {
                responsive: true,
                maintainAspectRatio: false,
                parsing: false,
                interaction: {
                    mode: 'nearest',
                    intersect: true,
                    axis: 'x'
                 },
                scales: {
                     x: {
                        type: 'time',
                        time: { unit: 'day', tooltipFormat: 'MMM dd, yyyy' },
                         title: { display: true, text: 'Date', color: '#ffffff' },
                        grid: { color: '#444444' },
                        ticks: { color: '#ffffff' }
                    },
                    y: {
                        title: { display: true, text: 'Price ₹', color: '#ffffff' },
                        grid: { color: '#444444' },
                        ticks: { color: '#ffffff' }
                    }
                },
              plugins: {
                    legend: { labels: { color: '#ffffff' } },
                   tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `₹${context.raw.y.toLocaleString(undefined, { maximumFractionDigits: 2 })}`;
                             }
                       }
                   }
                }
           }
        });

        console.log('Chart rendered successfully');
    }

    // Initial Fetch and Auto-Refresh Every 60 Seconds
    fetchCoinData();
    setInterval(fetchCoinData, 60000);
    fetchPosts(); // Fetch posts when the page loads
    setInterval(fetchPosts, 60000); // Refresh posts
});
