document.addEventListener('DOMContentLoaded', function () {
    var tabs = document.querySelectorAll('.tab a');
    tabs.forEach(tab => {
        tab.addEventListener('click', function (e) {
            e.preventDefault();
            var activeForms = document.querySelectorAll('.form-container.active');
            activeForms.forEach(form => {
                form.classList.remove('active');
                form.style.display = 'none';
            });

            var allTabs = document.querySelectorAll('.tab');
            allTabs.forEach(tab => {
                tab.classList.remove('active');
            });

            tab.parentNode.classList.add('active');
            var activeForm = document.querySelector(tab.getAttribute('href'));
            activeForm.classList.add('active');
            activeForm.style.display = 'block';
        });
    });
});

