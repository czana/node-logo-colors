###
  From Vibrant.js by Jari Zwarts
  Ported to node.js by AKFish

  Color algorithm class that finds variations on colors in an image.

  Credits
  --------
  Lokesh Dhakar (http://www.lokeshdhakar.com) - Created ColorThief
  Google - Palette support library in Android
###
Swatch = require('./swatch')
util = require('./util')
DefaultGenerator = require('./generator').Default
Filter = require('./filter')

module.exports =
class Vibrant
  @DefaultOpts:
    colorCount: 16
    quality: 5
    generator: new DefaultGenerator()
    Image: null
    Quantizer: require('./quantizer').MMCQ
    filters: []
    minPopulation: 35
    minRgbDiff: 15

  @from: (src) ->
    new Builder(src)

  quantize: require('quantize')

  _swatches: []

  constructor: (@sourceImage, opts = {}) ->
    @opts = util.defaults(opts, @constructor.DefaultOpts)
    @generator = @opts.generator

  getPalette: (cb) ->
    image = new @opts.Image @sourceImage, (err, image) =>
      if err? then return cb(err)
      try
        @_process image, @opts
        cb null, @swatches()
      catch error
        return cb(error)

  getSwatches: (cb) ->
    @getPalette cb

  _process: (image, opts) ->
    image.scaleDown(@opts)
    imageData = image.getImageData()

    quantizer = new @opts.Quantizer()
    quantizer.initialize(imageData.data, @opts)

    @allSwatches = quantizer.getQuantizedColors()

    image.removeCanvas()

  swatches: =>
    finalSwatches = []

    @allSwatches = @allSwatches.sort (a, b) ->
      b.getPopulation() - a.getPopulation()

    comparingPopulation = @getComparingPopulation(@allSwatches)

    for swatch in @allSwatches
      if @populationPercentage(swatch.getPopulation(), comparingPopulation) > @opts.minPopulation
        should_be_added = true

        for final_swatch in finalSwatches
          if Vibrant.Util.rgbDiff(final_swatch.rgb, swatch.rgb) < @opts.minRgbDiff
            should_be_added = false
            break

        if should_be_added
          finalSwatches.push swatch

    finalSwatches

  populationPercentage: (population, comparingPopulation) ->
    (population / comparingPopulation) * 100

  getComparingPopulation: (swatches) ->
    swatches[1].getPopulation()

module.exports.Builder =
class Builder
  constructor: (@src, @opts = {}) ->
    @opts.filters = util.clone Vibrant.DefaultOpts.filters

  maxColorCount: (n) ->
    @opts.colorCount = n
    @

  maxDimension: (d) ->
    @opts.maxDimension = d
    @

  addFilter: (f) ->
    if typeof f == 'function'
      @opts.filters.push f
    @

  removeFilter: (f) ->
    if (i = @opts.filters.indexOf(f)) > 0
      @opts.filters.splice(i)
    @

  clearFilters: ->
    @opts.filters = []
    @

  quality: (q) ->
    @opts.quality = q
    @

  minPopulation: (q) ->
    @opts.minPopulation = q
    @

  minRgbDiff: (q) ->
    @opts.minRgbDiff = q
    @

  useImage: (image) ->
    @opts.Image = image
    @

  useQuantizer: (quantizer) ->
    @opts.Quantizer = quantizer
    @

  build: ->
    if not @v?
      @v = new Vibrant(@src, @opts)
    @v

  getSwatches: (cb) ->
    @build().getPalette cb

  getPalette: (cb) ->
    @build().getPalette cb

  from: (src) ->
    new Vibrant(src, @opts)

module.exports.Util = util
module.exports.Swatch = Swatch
module.exports.Quantizer = require('./quantizer/')
module.exports.Generator = require('./generator/')
module.exports.Filter = require('./filter/')
